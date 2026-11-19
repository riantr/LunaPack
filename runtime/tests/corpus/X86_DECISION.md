# L3.5-3.7 x86 PE32 支持：Go/No-Go 结论（2026-11-19）

## 结论：**NO-GO（工具链硬限制），转为书面产品限制**

L3.5（产出 pe-i386 runtime + DLL + 宿主）、L3.6（Windows CI x86 leg）、L3.7
（32 位程序零落盘）**全部不实装**。这是 MoonBit 后端能力的硬限制，不是
"程序不支持"的托辞，也不是安全软件否决（区别于 L0.4 路径 A / L2.3 inline）。

## 证据

1. **无 32 位 Windows 目标。** 当前工具链 `moon 0.1.20261102` / `moonc
   v0.10.19`，`moon build --target` 的原生后端只产出宿主架构；moonc 内嵌的
   Windows 目标字符串只有：
   - `x86_64-pc-windows-msvc`
   - `aarch64-pc-windows-msvc`
   
   没有 `i686-pc-windows-msvc` / `i386-pc-windows-*`。`--target` 可选值只有
   `wasm, wasm-gc, js, native, llvm, all`，没有架构选择位。

2. **runtime 的指针算术全线 64 位。** 生成的 C 中约 1909 处 `int64_t`；
   `mapper.mbt` 只读 `PE32+` 魔数 `0x20b` 和 `MACHINE_AMD64 0x8664`，
   `mem.mbt` 的 `peek64/poke64`、`iat.mbt` 的 8 字节槽、`thunks.mbt` 的
   x64 `IO_STATUS_BLOCK`/`OBJECT_ATTRIBUTES` 布局，全部假设 64 位指针与
   x64 调用约定。这不是加一个编译开关能解决的，需要整套重写为 `pe-i386`
   语义（4 字节槽、`stdcall`、不同数据目录偏移、不同 NT 结构布局）。

3. **混合进程无法救场。** 64 位 `lpvirt.dll` 无法被 32 位进程加载（位数不
   匹配），也不能在 64 位宿主里映射并执行 32 位 PE32 映像（地址宽度与调用
   约定不兼容）。语料库 B4 样本 `enigmavb.exe` 机器类型实测 `0x014C`
   （PE32 i386），因此确实跑不起来。

## 处理

- 记为产品限制，写入 `runtime/README.md` 的 "Limits" 与 TODO 第 18 节。
- 32 位程序在 Tier B 中标记 `unsupported (toolchain)`，不计入通过数，也不
  当作"程序不支持"绕过——是运行时/工具链根本不产出 x86 产物。
- L3 的退出判据因此**部分满足**：L3.1-3.4 全过，L3.5-3.7 NO-GO。Tier B
  的 x86 程序验证永久顺延到"若未来引入 32 位后端再重启"，不阻塞 L4/L5/L6
  的 x64 路径（L4 子进程、L6 CLI/归档都只面向 x64）。

## 重启条件

只有当满足以下任一条，才重新评估 L3.5：
- MoonBit 官方提供 `i686-pc-windows-msvc`（或等价 32 位 Windows）原生目标；或
- 允许引入非 MoonBit 的 32 位 runtime（违背当前"纯 MoonBit、零依赖"约定，
  需用户重新拍板）。
