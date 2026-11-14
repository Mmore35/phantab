// Prints the on-screen state of every window a process owns, as JSON lines.
// Needs no permission for bounds/onscreen/layer; titles need Screen Recording.
import CoreGraphics
import Foundation
let pid = Int32(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as! [[String: Any]]
for w in list where (w[kCGWindowOwnerPID as String] as? Int32) == pid {
  let b = w[kCGWindowBounds as String] as! [String: Any]
  let o: [String: Any] = [
    "id": w[kCGWindowNumber as String] ?? 0, "layer": w[kCGWindowLayer as String] ?? 0,
    "onscreen": w[kCGWindowIsOnscreen as String] ?? false, "alpha": w[kCGWindowAlpha as String] ?? 1,
    "name": w[kCGWindowName as String] ?? "", "x": b["X"]!, "y": b["Y"]!, "w": b["Width"]!, "h": b["Height"]!,
  ]
  print(String(data: try! JSONSerialization.data(withJSONObject: o), encoding: .utf8)!)
}
