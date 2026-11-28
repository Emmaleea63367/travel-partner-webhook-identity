## 联票回调与对账的资料
JSON 文件为 UTF-8。每张表有 `id`，该编号在所属集合中唯一。空字符串表示没有值或不适用。零是明确观测值。除另有说明，数字时间以资料所用当地营业日的零点起算，单位为分钟。带发生与接收时间的记录保留两者，单独给出一项的记录无需再推定另一项。时间窗口含起点、不含到期点，日期另有日期规则。

### `members.json`
已登记成员公钥与可代表的路线范围。
字段为 `id`、`entity`、`key`、`routes`。

### `delegates.json`
合法的合办机构及代理行为成员范围。relay 仍需原成员签名，progress 是代理人自有声明。
字段为 `id`、`service`、`key`、`member`、`route`、`grant`。
所用外部记录引用为 `member` 对应 `members.id`。

### `endpoints.json`
控制身份来自预先核实的机构登记。地址一样可以是两个不同的承办身份。
字段为 `id`、`url`、`controller`、`member`、`from_time`、`until_time`。
所用外部记录引用为 `member` 对应 `members.id`。

### `lines.json`
联票应分别由成员确认的票行。
字段为 `id`、`ticket`、`route`、`member`、`net_cents`。
所用外部记录引用为 `member` 对应 `members.id`。

### `endpoint_ownership.json`
收件端独立确认的控制主体和用于收件身份验证的公钥。
字段为 `id`、`endpoint`、`holder`、`key`、`from_time`。
所用外部记录引用为 `endpoint` 对应 `endpoints.id`。

### `delivery.json`
发出、已收和未知分别来自不同时间的监测。
字段为 `id`、`endpoint`、`message`、`state`、`observed`、`received`。
所用外部记录引用为 `endpoint` 对应 `endpoints.id`。

### 本地 HTTP 交换
`wire/requests.json` 保存合成的请求。body 是发送方实际交付的原始字节的 Base64，不能先重排正文再验摘要。使用 RFC 9421 HTTP Message Signatures 的 Ed25519 子集，覆盖 @method、@target-uri、content-digest 和 notification-id，Signature-Input 有 created、keyid、alg。Content-Digest 使用 RFC 9530 的 SHA-256。`wire-capture.txt` 是样本中保留的原始签名输入。Domain 只作协议内标识。
转递的 forwarded 对象保留原成员的签名、keyid 和原消息 signed_bytes，可对其原始 JSON 字节直接验签。原成员的断言与合办机构实际签出的 HTTP 消息均有各自独立的身份。receive-control.json 存放旧、新两位收件端持有者为各自登记发出的签名，签名材料的格式与 forwarded 相同。发行方和端点使用的合成公钥在该目录内，所有发送时刻以资料给出的模拟营业日解释。

### 核验与核账代码
- `wireverify.py`：只做线路核验。对请求实际交付的 body 字节计算 RFC 9530 摘要，按 Signature-Input 实际列出的分量重建 RFC 9421 签名基底并以登记 keyid 的 Ed25519 公钥验签；强制 alg=ed25519 且必须覆盖 @method、@target-uri、content-digest、notification-id（请求目标、正文与本次投递）。forwarded 内层与 receive-control 声明用同一套“原始字节 + 独立签名”核验。
- `desk.py`：核账台规则。成员自签才产生成员事实；合办机构转递需 relay 授权且内外两层分别验签，progress 授权只能发明示代办的进度通知，不形成核销、冲销或结清事实。票行事实绑定 line/member/route，revision 高者为现行事实，旧版与所据字节保留留档。收件端按 endpoint_ownership 的控制身份与控制窗口认定；窗口外回执记为迟到回执，只证明旧持有者曾收到某版。`reconcile()` 可重复运行，逐项列出缺哪一方的成员事实、哪一次投递确认，未全部独立证明前票款一律待核；`trace_message`/`ticket_view` 对成员做与己有关的访问限制。
