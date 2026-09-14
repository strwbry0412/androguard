from androguard.misc import AnalyzeAPK
import argparse


PACKAGE = "Lowasp/sat/agoat/"


def find_method(dx, method_ref):
    """
    method_refからEncodedMethodを探す。
    """

    class_name, rest = method_ref.split("->", 1)
    method_name, descriptor = rest.split("(", 1)
    descriptor = "(" + descriptor

    for method in dx.get_methods():
        encoded = method.get_method()

        if (
            encoded.get_class_name() == class_name
            and encoded.get_name() == method_name
            and encoded.get_descriptor() == descriptor
        ):
            return encoded

    return None


def find_method_analysis(dx, method_ref):
    """
    method_refからMethodClassAnalysisを探す。
    """

    class_name, rest = method_ref.split("->", 1)
    method_name, descriptor = rest.split("(", 1)
    descriptor = "(" + descriptor

    for method in dx.get_methods():
        encoded = method.get_method()

        if (
            encoded.get_class_name() == class_name
            and encoded.get_name() == method_name
            and encoded.get_descriptor() == descriptor
        ):
            return method

    return None


def get_called_methods(method):
    """
    メソッド内のinvoke命令から
    呼び出しているメソッドを取得する。
    """

    calls = []

    for instruction in method.get_instructions():

        if not instruction.get_name().startswith("invoke-"):
            continue

        operands = instruction.get_operands()

        method_ref = operands[-1][2]

        calls.append(method_ref)

    return calls


def find_listener_class(instructions, set_listener_index):
    """
    setOnClickListener() に渡されたregisterから、
    直前のnew-instanceを探してlistener classを特定する。
    """

    instruction = instructions[set_listener_index]

    operands = instruction.get_operands()

    # setOnClickListener(button, listener)
    listener_register = operands[1][1]

    for previous in reversed(
        instructions[:set_listener_index]
    ):

        if previous.get_name() != "new-instance":
            continue

        previous_operands = (
            previous.get_operands()
        )

        register = previous_operands[0][1]

        if register == listener_register:

            listener_class = (
                previous_operands[-1][2]
            )

            return listener_class

    return None


def find_onclick(dx, listener_class):
    """
    listener classからonClick()を探す。
    """

    for method in dx.get_methods():

        encoded = method.get_method()

        if (
            encoded.get_class_name()
            == listener_class
            and encoded.get_name()
            == "onClick"
        ):
            return encoded

    return None


def find_navigation_target(dx, callback):
    """
    callback内の

        const-class
        Intent.<init>
        startActivity

    を追跡して、遷移先Activityを取得する。
    """

    instructions = list(
        callback.get_instructions()
    )

    class_register = None
    target_activity = None

    intent_register = None

    for instruction in instructions:

        name = instruction.get_name()
        operands = instruction.get_operands()

        if name == "const-class":

            class_register = operands[0][1]

            target_activity = (
                operands[-1][2]
            )

        elif name.startswith("invoke-"):

            method_ref = operands[-1][2]

            if "Intent;-><init>" in method_ref:

                intent_register = (
                    operands[0][1]
                )

                class_arg_register = (
                    operands[2][1]
                )

                if (
                    class_arg_register
                    == class_register
                ):
                    pass

            elif "->startActivity(" in method_ref:

                if intent_register is None:
                    continue

                intent_arg_register = (
                    operands[1][1]
                )

                if (
                    intent_arg_register
                    == intent_register
                ):
                    return target_activity

    return None


def print_callback(
    dx,
    instructions,
    set_listener_index,
    depth
):
    """
    setOnClickListener()からcallbackを解析する。
    """

    indent = "    " * depth

    listener_class = find_listener_class(
        instructions,
        set_listener_index
    )

    if listener_class is None:
        return

    print(
        indent + "└─ CALLBACK"
    )

    print(
        indent
        + "    listener: "
        + listener_class
    )

    callback = find_onclick(
        dx,
        listener_class
    )

    if callback is None:
        return

    print(
        indent
        + "    └─ onClick()"
    )

    target = find_navigation_target(
        dx,
        callback
    )

    if target is not None:

        print(
            indent
            + "        └─ navigation: "
            + target
        )


def print_call_tree(
    dx,
    method,
    depth=0,
    max_depth=1,
    path=None
):
    """
    target methodから呼び出し先を辿って
    Call Treeを表示する。

    depth:
        現在の深さ

    max_depth:
        最大のCall Tree深度

    path:
        現在の呼び出し経路。
        同じメソッドを経路内で再度訪れた場合、
        無限再帰を防ぐ。
    """

    if path is None:
        path = set()

    method_key = (
        method.get_class_name(),
        method.get_name(),
        method.get_descriptor()
    )

    if method_key in path:
        return

    path = path | {method_key}

    # 指定深度に到達したら、
    # 現在のメソッドの中身は展開しない
    if depth >= max_depth:
        return

    instructions = list(
        method.get_instructions()
    )

    for instruction in instructions:

        if not instruction.get_name().startswith(
            "invoke-"
        ):
            continue

        operands = instruction.get_operands()

        method_ref = operands[-1][2]

        # callback登録
        if "setOnClickListener" in method_ref:

            # callbackは通常のCALLとは別扱い
            print_callback(
                dx,
                instructions,
                instructions.index(instruction),
                depth + 1
            )

            continue

        called = find_method(
            dx,
            method_ref
        )

        if called is None:
            continue

        # コンストラクタは通常のCALL Treeから除外
        if called.get_name() == "<init>":
            continue

        print(
            "    " * (depth + 1)
            + "└─ CALL "
            + method_ref
        )

        # アプリ内メソッドだけ再帰的に展開
        if not called.get_class_name().startswith(
            PACKAGE
        ):
            continue

        # ExternalMethodなど、
        # 命令列を持たないものは展開しない
        if not hasattr(
            called,
            "get_instructions"
        ):
            continue

        print_call_tree(
            dx,
            called,
            depth=depth + 1,
            max_depth=max_depth,
            path=path
        )


def get_callers(dx, method):
    """
    APK内を走査して、
    指定したmethodを直接呼び出している
    メソッドを取得する。

    戻り値:
        [(caller_method, ...), ...]
    """

    target_ref = (
        method.get_class_name()
        + "->"
        + method.get_name()
        + method.get_descriptor()
    )

    callers = []
    caller_keys = set()

    for caller_analysis in dx.get_methods():

        caller = caller_analysis.get_method()

        # 命令列を持たないExternalMethodなどは除外
        if not hasattr(
            caller,
            "get_instructions"
        ):
            continue

        for instruction in caller.get_instructions():

            if not instruction.get_name().startswith(
                "invoke-"
            ):
                continue

            operands = instruction.get_operands()

            method_ref = operands[-1][2]

            if method_ref != target_ref:
                continue

            caller_key = (
                caller.get_class_name(),
                caller.get_name(),
                caller.get_descriptor()
            )

            if caller_key not in caller_keys:

                caller_keys.add(caller_key)

                callers.append(caller)

            break

    return callers


def print_caller_tree(
    dx,
    method,
    depth=0,
    max_depth=1,
    path=None
):
    """
    target methodを呼び出しているcallerを辿って
    Caller Treeを表示する。

    target
        ↑
        caller
        ↑
        caller's caller

    の方向に探索する。
    """

    if path is None:
        path = set()

    method_key = (
        method.get_class_name(),
        method.get_name(),
        method.get_descriptor()
    )

    if method_key in path:
        return

    path = path | {method_key}

    # 指定深度に到達したら、
    # それ以上callerを探さない
    if depth >= max_depth:
        return

    callers = get_callers(
        dx,
        method
    )

    for caller in callers:

        print(
            "    " * (depth + 1)
            + "└─ CALLED FROM "
            + caller.get_class_name()
            + "->"
            + caller.get_name()
            + caller.get_descriptor()
        )

        print_caller_tree(
            dx,
            caller,
            depth=depth + 1,
            max_depth=max_depth,
            path=path
        )


def summarize_method(dx, method):
    """
    メソッドの概要を取得する。

    - 通常のメソッド呼び出し
    - callback登録
    - callbackの処理
    - navigation
    - 分岐命令

    を収集する。
    """

    summary = {
        "calls": [],
        "callbacks": [],
        "branches": [],
    }

    instructions = list(
        method.get_instructions()
    )

    for i, instruction in enumerate(
        instructions
    ):

        name = instruction.get_name()

        if name.startswith("invoke-"):

            operands = instruction.get_operands()

            method_ref = operands[-1][2]

            # callback登録
            if "setOnClickListener" in method_ref:

                listener_class = (
                    find_listener_class(
                        instructions,
                        i
                    )
                )

                callback = None
                navigation_target = None

                if listener_class is not None:

                    callback = find_onclick(
                        dx,
                        listener_class
                    )

                    if callback is not None:

                        navigation_target = (
                            find_navigation_target(
                                dx,
                                callback
                            )
                        )

                summary["callbacks"].append({
                    "instruction": i,
                    "method": method_ref,
                    "listener": listener_class,
                    "callback": (
                        callback.get_name()
                        if callback is not None
                        else None
                    ),
                    "navigation": navigation_target,
                })

                continue

            # コンストラクタはCALLSから除外
            if "-><init>(" in method_ref:
                continue

            summary["calls"].append({
                "instruction": i,
                "method": method_ref,
            })

        elif name.startswith("if-"):

            operands = instruction.get_operands()

            target = operands[-1][1]

            summary["branches"].append({
                "instruction": i,
                "opcode": name,
                "target": target,
            })

    return summary


def print_method_summary(dx, method):

    summary = summarize_method(
        dx,
        method
    )

    print()
    print("=== Method Summary ===")

    print(
        method.get_class_name()
        + "->"
        + method.get_name()
        + method.get_descriptor()
    )

    print()
    print("CALLS")

    if not summary["calls"]:

        print("    none")

    else:

        # 同じメソッド呼び出しを集約
        call_counts = {}

        for call in summary["calls"]:

            method_ref = call["method"]

            if method_ref not in call_counts:
                call_counts[method_ref] = 0

            call_counts[method_ref] += 1

        for method_ref, count in call_counts.items():

            if count == 1:

                print(
                    "    " + method_ref
                )

            else:

                print(
                    "    "
                    + method_ref
                    + " × "
                    + str(count)
                )

    print()
    print("CALLBACKS")

    if not summary["callbacks"]:

        print("    none")

    else:

        for callback in summary["callbacks"]:

            print(
                "    ["
                + str(callback["instruction"])
                + "] "
                + callback["method"]
            )

            print(
                "        listener: "
                + str(callback["listener"])
            )

            print(
                "        callback: "
                + str(callback["callback"])
                + "()"
            )

            if callback["navigation"] is not None:

                print(
                    "        navigation: "
                    + callback["navigation"]
                )

    print()
    print("BRANCHES")

    if not summary["branches"]:

        print("    none")

    else:

        for branch in summary["branches"]:

            print(
                "    ["
                + str(branch["instruction"])
                + "] "
                + branch["opcode"]
                + " -> "
                + str(branch["target"])
            )


def main():

    parser = argparse.ArgumentParser(
        description="Android APK call tree analyzer"
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum call tree depth (default: 2)"
    )

    parser.add_argument(
        "--up-depth",
        type=int,
        default=0,
        help="Maximum caller tree depth (default: 0)"
    )

    args = parser.parse_args()

    if args.depth < 0:

        parser.error(
            "--depth must be 0 or greater"
        )

    if args.up_depth < 0:

        parser.error(
            "--up-depth must be 0 or greater"
        )

    apk_path = "AndroGoat.apk"

    target_ref = (
        "Lowasp/sat/agoat/MainActivity;"
        "->_$_findCachedViewById(I)Landroid/view/View;"
    )

    a, d, dx = AnalyzeAPK(
        apk_path
    )

    target = find_method(
        dx,
        target_ref
    )

    if target is None:

        print("method not found")

        return

    # ==========================
    # Caller Tree
    # ==========================

    if args.up_depth > 0:

        print("=== Caller Tree ===")

        print(
            "└─ "
            + target.get_class_name()
            + "->"
            + target.get_name()
            + target.get_descriptor()
        )

        print_caller_tree(
            dx,
            target,
            depth=0,
            max_depth=args.up_depth
        )

        print()

    # ==========================
    # Call Tree
    # ==========================

    print("=== Call Tree ===")

    print(
        "└─ "
        + target.get_class_name()
        + "->"
        + target.get_name()
        + target.get_descriptor()
    )

    print_call_tree(
        dx,
        target,
        depth=0,
        max_depth=args.depth
    )

    # ==========================
    # Method Summary
    # ==========================

    print_method_summary(
        dx,
        target
    )


if __name__ == "__main__":
    main()