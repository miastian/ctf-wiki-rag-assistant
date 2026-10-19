"""Versioned evidence corrections and bounded literal arithmetic, never user code execution."""
import ast
import hashlib
import operator
import re


CORRECTIONS = ({
    'id': 'rsa-value-vs-encoded-length-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:crypto/asymmetric/rsa/rsa_e_attack.md',
    'conflicting_terms': ['e 为 3', 'm^3'],
    'correction': '未取模的直接开根条件针对明文整数值 m^e<N，不是密文余数 c<N。'
                  '编码字节长度可能含前导零，不能把256^(e*L)<N这样的上界充分条件写成恢复明文的必要条件或等价条件。'
                  '实际值、编码和N均未知时，不推断flag字节数；回答假设是否成立即可，不追加未请求的长度估计。',
    'authorities': ['https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_e_attack/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'sql-input-binding-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:web/sqli.md',
    'section_suffix': '基本概念',
    'conflicting_terms': ['输入参数', 'SQL'],
    'correction': '判断拼接必须看实际构造代码，不能从查询使用了用户值就断言发生字符串拼接。'
                  '预处理语句的占位符与绑定参数值需要和拼进 SQL 语法的字符串区分；'
                  '缺少代码时说明要检查的构造关系，不直接判定有注入。',
    'authorities': ['https://dev.mysql.com/doc/refman/8.4/en/sql-prepared-statements.html'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'pcapng-block-format-scope-v1',
    'document': 'ctf-wiki:misc/traffic/fix.md',
    'conflicting_terms': ['Section Header', 'Interface Description', 'Block Total Length', 'LinkType'],
    'correction': '这里展示的是 pcapng 的块结构，不是传统 pcap 的通用结构。'
                  'Section Header Block、Interface Description Block 等应明确限定 pcapng；'
                  '不能仅因扩展名为 pcap 就按这些块解析，先确认实际捕获文件格式。',
    'authorities': ['https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/06/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'dynelf-read-side-effects-v1',
    'document': 'ctf-wiki:pwn/linux/user-mode/summary/get-address.md',
    'section_suffix': '`pwnlib.dynelf`',
    'conflicting_terms': ['环境变量被覆盖'],
    'correction': '内存读取本身不会覆盖被读取的环境变量。write 从给定缓冲区向文件描述符输出字节，'
                  'DynELF 依赖能读取任意地址的泄露函数；不能据本段泛称向高地址读会覆盖环境变量。'
                  '真实泄露链中是否有写入或栈破坏必须结合代码判断，不能把多读一些当作通用修复。',
    'authorities': ['https://docs.pwntools.com/en/stable/dynelf.html',
                    'https://man7.org/linux/man-pages/man2/write.2.html'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'tcache-historical-example-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:pwn/linux/user-mode/heap/ptmalloc2/tcache-attack.md',
    'conflicting_terms': ['tcache', '0x408'],
    'correction': '该文是历史实现与例题，不能当作任意版本 glibc 的统一行为。'
                  '0x408 请求范围与每 bin 默认 7 块应限定为本节所示实现/默认配置，源码明确 count 可调。'
                  '无重复释放检查的 tcache_dup 示例明确来自 glibc_2.26，不能套到版本未知环境。'
                  '先确认 libc/ld、架构和 tunables；未知时仅描述原文例子并询问版本，不追加利用流程。',
    'authorities': ['https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'stack-example-abi-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:pwn/linux/user-mode/stackoverflow/x86/stack-intro.md',
    'section_suffix': '函数调用栈',
    'conflicting_terms': ['x86', 'x64'],
    'correction': '本节画的是特定调用约定下的栈布局。不要把本节 x86 栈上传参示意当成所有 x86 调用约定。'
                  '通用解释只需说明返回信息、局部数据及溢出参数；具体传参位置须确认 ABI。'
                  '也不要为泛问堆砌其他架构的规则。引用 MIPS32 示例必须保留32位范围，不能泛称全部 MIPS。',
    'authorities': ['https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stack-intro/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'png-stepic-evidence-limit-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:misc/picture/png.md',
    'section_suffix': '隐写软件',
    'conflicting_terms': ['Stepic'],
    'correction': '本节只有 Stepic 名称和链接，没有密码、导出流程、命令或参数说明。'
                  '最多介绍该软件是原文列出的线索，不能据此追加密码/导出操作，也不能假称读过链接内容。',
    'authorities': ['https://ctf-wiki.org/misc/picture/png/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'php-execution-sinks-scope-v1',
    'document': 'ctf-wiki:web/php/php.md',
    'section_suffix': '直接执行代码',
    'conflicting_terms': ['assert', 'system', 'escapeshellcmd'],
    'correction': '该列表混合了 PHP 求值、操作系统命令和转义函数，不能统称 PHP 代码执行入口。'
                  'eval 求值 PHP 字符串；assert 对字符串求值的旧行为在 PHP 7.2 弃用、PHP 8.0 移除，'
                  '旧版本也依赖断言配置。system/exec/shell_exec/passthru 执行操作系统命令，'
                  '不等于把读入的文件内容作为 PHP 解释。escapeshellcmd 只转义命令字符串，本身不执行。'
                  '仅有 fopen 路径可控不能推断 PHP 执行；应确认实际后续调用、参数、版本和配置。',
    'authorities': ['https://www.php.net/manual/en/function.assert.php',
                    'https://www.php.net/manual/en/function.eval.php',
                    'https://www.php.net/manual/en/function.system.php',
                    'https://www.php.net/manual/en/function.escapeshellcmd.php'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'php-interpolation-source-scope-v1',
    'document': 'ctf-wiki:web/php/php.md',
    'section_suffix': 'Curly Syntax',
    'conflicting_terms': ['花括号', 'foobar'],
    'correction': '本节例子是 PHP 源码中的插值表达式、反引号和变量函数调用，'
                  '不能概括为任意字符串或模板中的花括号都执行 PHP。读取文件得到的字符串再放入变量或输出，'
                  '不会因此重新作为 PHP 源码解析。必须确认具体求值入口和可控源码上下文；'
                  '不能以文件内容含花括号或被字符串插值输出作为执行证明。',
    'authorities': ['https://www.php.net/manual/en/language.types.string.php',
                    'https://www.php.net/manual/en/language.operators.execution.php',
                    'https://www.php.net/manual/en/functions.variable-functions.php'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'rsa-short-pad-bound-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:crypto/asymmetric/rsa/rsa_coppersmith_attack.md',
    'section_suffix': 'Coppersmith’s short-pad attack > 攻击原理',
    'conflicting_terms': ['floor', 'e^2', 'e^{2}'],
    'correction': '短填充路线不是只要同消息有两份密文就适用。须保留原文的共同模数、'
                  '消息关系 M1=2^m*M+r1、M2=2^m*M+r2 及填充界 m=floor(k/e^2)（k 为模数位数）。'
                  '在 e=65537 时，该界对常见 RSA 模数位数为 0，不能把这条低指数例题当作当前可行方案。'
                  '缺少可满足的界限、相关消息关系或多份密文时只说明资料不足，不推荐为可执行下一步。',
    'authorities': ['https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_coppersmith_attack/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'rsa-leak-relation-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:crypto/asymmetric/rsa/rsa_theory.md',
    'section_suffix': '2018 CodeGate CTF Rsababy',
    'conflicting_terms': ['deadbeef', 'gcd'],
    'correction': '本例的 gcd 构造依赖精确泄露关系 g=d*(p-0xdeadbeef) 和已知常数，'
                  '不是见到任意 h/g/d 泄露就能套用。须先从实际题面建立同余与整除关系，'
                  '再验证 gcd 是否给出非平凡因子；变量名相同不是依据。已知 p/q 可直接分解，'
                  '已知 d 的恢复方法也不能由本例公式泛化。用户仅给 n/e/c 时不追加这一例题的攻击路线。',
    'authorities': ['https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_theory/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'php-file-read-include-v1',
    'document': 'ctf-wiki:web/php/php.md',
    'section_suffix': '文件包含',
    'conflicting_terms': ['readfile()', 'fopen()'],
    'correction': '此 Wiki 小节将读取函数混入文件包含列表。readfile() 读取并输出文件，'
                  'fopen() 打开文件流，不能因此断言它们像 include/require 一样包含并求值 PHP 文件。'
                  '分析时区分文件读取/泄露与文件包含求值，不能把用户可控路径直接等同于代码执行。',
    'authorities': ['https://www.php.net/manual/en/function.readfile.php',
                    'https://www.php.net/manual/en/function.fopen.php',
                    'https://www.php.net/manual/en/function.include.php'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'php-comparison-version-v1',
    'document': 'ctf-wiki:web/php/php.md',
    'section_suffix': '内置函数的参数的松散性',
    'conflicting_terms': ['md5', 'strcmp', 'in_array', 'switch'],
    'correction': '本节包含旧版 PHP 的行为，未标明版本，不能当作跨版本绕过规则。'
                  'PHP 8 中向 md5()/strcmp() 传数组属于不兼容参数类型，会抛出 TypeError，'
                  '不能按旧例假设返回 null 后比较相等。PHP 8 改变了数字与非数字字符串的松散比较；'
                  '旧例中非数字字符串匹配整数 0 的 in_array/switch 推论不能直接沿用。'
                  '非严格比较并未全部消失；应确认实际 PHP 版本、参数类型和 strict 参数再判断，'
                  '未知版本时仅指出待核实的比较点，不推荐旧例作为已可用绕过。',
    'authorities': ['https://www.php.net/manual/en/functions.internal.php',
                    'https://www.php.net/manual/en/migration80.incompatible.php',
                    'https://www.php.net/manual/en/function.in-array.php'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'rsa-message-coprimality-v1',
    'document': 'ctf-wiki:crypto/asymmetric/rsa/rsa_theory.md',
    'section_suffix': '消息加密',
    'conflicting_terms': ['互质'],
    'correction': '本节把 m 与 N 互质写成要求，范围过窄；同文档正确性证明另含不互质分支。'
                  '对于两个不同素数 p,q 的标准 RSA，消息代表元范围为 0<=m<N，'
                  '不要求 gcd(m,N)=1 才能加解密往返；欧拉定理的互质证明只是其中一个分支。'
                  '例如 N=55,e=3,d=27,m=5 时 c=15，15^27 mod 55=5。'
                  '这只是教科书模幂关系，不代表无填充或任意分块是安全的生产加密方案。',
    'authorities': ['https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_theory/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'png-ihdr-data-scope-v1',
    'document': 'ctf-wiki:misc/picture/png.md',
    'section_suffix': 'IHDR',
    'conflicting_terms': ['13', '前8'],
    'correction': '本节的 13 字节及前 8 字节均指 IHDR 的 Chunk Data，而非整个 IHDR 块。'
                  '数据区前 4 字节是宽、后 4 字节是高。完整块含 Length(4)、Type(4)、'
                  'Data(13)、CRC(4)，共 25 字节；完整块前 8 字节是 Length 和 Type。'
                  '仅 Data+CRC 为 17 字节；从 PNG 文件起始包含签名到完整 IHDR 结束为 33 字节。'
                  '介绍宽高时必须明确写 IHDR 数据区，不能简写为 IHDR 块前 8 字节。'
                  'CRC 匹配只说明候选 Type+Data 与给定 CRC 一致；将其用于恢复还依赖原始 CRC 未被改动、'
                  '其余字段正确等假设。须把命中值作为有前提的恢复候选，再检查块结构及显示结果，不能无条件宣称已找到真实宽高或 flag。',
    'authorities': ['https://ctf-wiki.org/misc/picture/png/'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'x64-address-scope-v1',
    'document': 'ctf-wiki:pwn/linux/user-mode/stackoverflow/x86/stack-intro.md',
    'section_suffix': '函数调用栈',
    'conflicting_terms': ['0x00007FFFFFFFFFFF'],
    'correction': '本节把地址不大于 0x00007FFFFFFFFFFF 写成所有 x64 的限制，范围过宽。'
                  '这不是 System V AMD64 ABI 的通用地址上限。Linux 内核文档说明，'
                  '五级分页可提供 56 位用户虚拟地址空间，虽然默认仍通常不在 47 位以上分配，'
                  '程序可请求更宽地址。不能从某些低地址的有效位数推断指针对象只有 6 字节。'
                  '讨论栈与参数时无需引入无关地址上限；若确需分析地址，须确认平台、分页模式和地址空间。',
    'authorities': ['https://docs.kernel.org/arch/x86/x86_64/5level-paging.html'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'mysql-concat-aggregation-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:web/sqli.md',
    'section_suffix': '注入常见参数',
    'conflicting_terms': ['concat()', 'group_concat()'],
    'correction': '这里需要区分 MySQL 函数语义，并非把原列表判为错误。CONCAT() 拼接传入的字符串参数，'
                  '例如同一行的 username 和 password，不会自行聚合多行。GROUP_CONCAT() 才是把一组行的非 NULL 值拼接为结果的聚合函数。'
                  '不能说多行数据可以用 concat/group_concat 而不加区分；函数名列表也不支持额外的探测操作。',
    'authorities': ['https://dev.mysql.com/doc/refman/8.4/en/string-functions.html#function_concat',
                    'https://dev.mysql.com/doc/refman/8.4/en/aggregate-functions.html#function_group-concat'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'elf-program-header-class-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:executable/elf/structure/basic-info.md',
    'section_suffix': 'Program Header Table > 概述',
    'conflicting_terms': ['Elf32_Phdr'],
    'correction': '本节展示的 Elf32_Phdr 是 ELF32 的程序头条目，不是所有 ELF 位宽的统一结构。'
                  'ELF64 对应 Elf64_Phdr，字段位宽和排列可能不同；须先根据 EI_CLASS 区分，再讨论结构与偏移。'
                  '若仅介绍通用骨架，可称程序头条目数组，不把 Elf32_Phdr 直接泛化到 ELF64。',
    'authorities': ['https://gabi.xinuos.com/elf/07-pheader.html'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'wireshark-protocol-hierarchy-name-v1',
    'document': 'ctf-wiki:misc/traffic/protocols/wireshark.md',
    'section_suffix': 'Protocol History(协议分级)',
    'conflicting_terms': ['Protocol History'],
    'correction': '本节把协议分级窗口误写为 Protocol History。官方名称是 Protocol Hierarchy，'
                  '可从 Statistics 菜单进入；介绍操作时使用这个名称，不能指导用户寻找 Protocol History 菜单。'
                  '原文描述的协议树、包数和字节数统计用途仍可引用。',
    'authorities': ['https://www.wireshark.org/docs/wsug_html_chunked/ChStatHierarchy.html',
                    'https://www.wireshark.org/docs/wsug_html_chunked/ChUseStatisticsMenuSection.html'],
    'reviewed_on': '2026-10-17',
}, {
    'id': 'zip-known-plaintext-cipher-scope-v1',
    'kind': 'scope_clarification',
    'document': 'ctf-wiki:misc/archive/zip.md',
    'section_contains': '明文攻击',
    'conflicting_terms': ['12', '明文', 'pkcrack', 'ARCHPR'],
    'correction': '本节描述的已知明文攻击针对传统 PKWARE/ZipCrypto 流加密，不能泛称任意加密 ZIP。'
                  '应先确认目标条目的加密算法，不能仅因有 12 字节明文就将该路线套到 AES ZIP。'
                  '对应的已知字节需与被加密的数据流对齐，使用压缩时还需匹配相应压缩数据；工具的连续字节要求须以对应工具文档为准。'
                  '7-Zip 是程序，7z 和 ZIP 是格式，程序也能生成 ZIP；不能说用7z工具就必然使用另一种压缩算法。'
                  '匹配的是具体压缩方法、参数及所得字节流，使用同一软件本身不能证明匹配。'
                  '不要把新工具的稀疏明文选项当作原文 pkcrack 的参数。',
    'authorities': ['https://github.com/kimci86/bkcrack#overview',
                    'https://github.com/kimci86/bkcrack#recover-internal-keys',
                    'https://www.7-zip.org/'],
    'reviewed_on': '2026-10-17',
})


def evidence_corrections(evidence):
    """Attach a reviewable erratum without changing original evidence text."""
    found = []
    for source in evidence:
        for item in CORRECTIONS:
            section = source.get('section', '')
            section_matches = (section.endswith(item['section_suffix']) if 'section_suffix' in item
                               else item.get('section_contains', '') in section)
            if (source['doc_id'] == item['document'] and section_matches and
                    any(term in source['text'] for term in item['conflicting_terms'])):
                found.append({**item, 'evidence_number': source['number'],
                              'chunk_id': source['id'],
                              'original_text_sha256': hashlib.sha256(source['text'].encode()).hexdigest()})
    return found


def source_scopes(evidence):
    """Surface literal environment/ABI/condition statements, without inventing scope."""
    notes = []
    pattern = re.compile(r'ABI|System V|Windows|Linux|FreeBSD|macOS|glibc|MIPS32|AArch32|PHP\s*[0-9]|'
                         r'register_globals|仅当|只有|适用|要求|满足|前提|条件', re.I)
    for source in evidence:
        fragments = []
        for paragraph in re.split(r'\n\s*\n', source['text']):
            if pattern.search(paragraph):
                fragments.append(paragraph[:1200])
        if fragments:
            notes.append({'evidence_number': source['number'], 'chunk_id': source['id'],
                          'scope_excerpts': fragments[:4],
                          'excerpts_are_partial': any(len(p)>1200 for p in re.split(r'\n\s*\n',source['text']) if pattern.search(p)) or len(fragments)>4})
    return notes


def scope_violation(answer, evidence):
    """Reject a demonstrated ABI generalization; never fabricate a correction silently."""
    relevant = any('System V AMD64 ABI' in s['text'] and 'RDI' in s['text'] and 'R9' in s['text']
                   for s in evidence)
    if (relevant and re.search(r'RDI', answer, re.I) and re.search(r'R9', answer, re.I)
            and re.search(r'参数|传参|调用约定|arguments?|parameters?', answer, re.I)):
        if not re.search(r'System\s*V|SysV|AMD64\s*ABI', answer, re.I):
            return '六寄存器传参说明缺少 System V AMD64 ABI 适用范围'
    return None


OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
       ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.BitXor: operator.xor,
       ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
       ast.LShift: operator.lshift, ast.RShift: operator.rshift}


def literal_value(node, names=None, depth=0):
    """Interpret only bounded integer/list expressions; no eval/exec/calls/attributes."""
    names = names or {}
    if depth > 16:
        raise ValueError('expression too deep')
    def sub(n, env=names):
        return literal_value(n, env, depth + 1)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        result = node.value
    elif isinstance(node, ast.Name) and node.id in names:
        result = names[node.id]
    elif isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 128:
        result = [sub(n) for n in node.elts]
        if any(type(v) is not int for v in result):
            raise ValueError('integer lists only')
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
        val = sub(node.operand)
        if type(val) is not int:
            raise ValueError('integer operand required')
        result = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Invert: operator.invert}[type(node.op)](val)
    elif isinstance(node, ast.BinOp) and type(node.op) in OPS:
        left, right = sub(node.left), sub(node.right)
        if type(left) is not int or type(right) is not int:
            raise ValueError('integer operands required')
        if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= 256:
            raise ValueError('shift out of range')
        result = OPS[type(node.op)](left, right)
    elif isinstance(node, ast.ListComp) and len(node.generators) == 1:
        gen = node.generators[0]
        if not isinstance(gen.target, ast.Name) or gen.ifs or gen.is_async:
            raise ValueError('unsupported comprehension')
        values = sub(gen.iter)
        if not isinstance(values, list) or len(values) > 128:
            raise ValueError('literal integer iterable required')
        result = [sub(node.elt, {**names, gen.target.id: value}) for value in values]
        if any(type(v) is not int for v in result):
            raise ValueError('integer result required')
    else:
        raise ValueError('unsupported expression')
    if type(result) is int and result.bit_length() > 256:
        raise ValueError('integer too large')
    return result


def arithmetic_checks(materials):
    checks = []
    for material in materials:
        text = material['text']
        blocks = re.findall(r'```(?:python|py)?\s*\n(.*?)```', text, re.S)
        # Standalone integer expressions such as 0x42 ^ 7 are also accepted.
        if not blocks and len(text.strip()) <= 300:
            blocks = [text.strip()]
        for block in blocks[:4]:
            if len(block) > 4000:
                continue
            try:
                tree = ast.parse(block)
                if len(list(ast.walk(tree))) > 512 or len(tree.body) > 16:
                    continue
                names, pending = {}, []
                for stmt in tree.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        value = literal_value(stmt.value, names)
                        names[stmt.targets[0].id] = value
                        expr = ast.get_source_segment(block, stmt.value)
                    elif isinstance(stmt, ast.Expr):
                        value = literal_value(stmt.value, names)
                        expr = ast.get_source_segment(block, stmt.value)
                    else:
                        raise ValueError('not a literal arithmetic block')
                    pending.append({'message_id': material['message_id'], 'expression': expr, 'result': value,
                                    'method': 'bounded_integer_ast_v1', 'user_code_executed': False})
                checks.extend(pending)
            except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError, RecursionError):
                continue
    return checks
