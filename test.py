from androguard.misc import AnalyzeAPK


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
    path=None
):
    """
    メソッドの呼び出し関係を表示する。

    - 通常のメソッド呼び出し → CALL
    - setOnClickListener → CALLBACK
    - 外部メソッド → 表示のみ
    - constructor → 表示しない
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

    instructions = list(
        method.get_instructions()
    )

    for i, instruction in enumerate(
        instructions
    ):

        if not instruction.get_name().startswith(
            "invoke-"
        ):
            continue

        operands = instruction.get_operands()

        method_ref = operands[-1][2]

        # --------------------------------
        # CALLBACK
        # --------------------------------

        if "setOnClickListener" in method_ref:

            print_callback(
                dx,
                instructions,
                i,
                depth + 1
            )

            continue

        # --------------------------------
        # 通常のCALL
        # --------------------------------

        called = find_method(
            dx,
            method_ref
        )

        if called is None:
            continue

        # constructorはスキップ
        if called.get_name() == "<init>":
            continue

        print(
            "    " * (depth + 1)
            + "└─ CALL "
            + method_ref
        )

        # 外部コードはここで終了
        if not called.get_class_name().startswith(
            PACKAGE
        ):
            continue

        # 命令列を持たないものも終了
        if not hasattr(
            called,
            "get_instructions"
        ):
            continue

        print_call_tree(
            dx,
            called,
            depth + 1,
            path
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

    instructions = list(method.get_instructions())

    for i, instruction in enumerate(instructions):
        name = instruction.get_name()

        if name.startswith("invoke-"):
            operands = instruction.get_operands()
            method_ref = operands[-1][2]

            # callback登録
            if "setOnClickListener" in method_ref:
                listener_class = find_listener_class(instructions, i)
                callback = None
                navigation_target = None

                if listener_class is not None:
                    callback = find_onclick(dx, listener_class)

                    if callback is not None:
                        navigation_target = find_navigation_target(
                            dx,
                            callback
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
    summary = summarize_method(dx, method)

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
                print("    " + method_ref)
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

    apk_path = "AndroGoat.apk"

    target_ref = (
        "Lowasp/sat/agoat/MainActivity;"
        "->onCreate(Landroid/os/Bundle;)V"
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
        depth=0
    )

    print_method_summary(
        dx,
        target
    )


if __name__ == "__main__":
    main()