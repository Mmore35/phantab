// Small macOS helper for the trial. None of these calls asks for a permission.
//   front                      pid of the frontmost app
//   locked                     1 when the login screen is up (on-screen checks mean nothing then)
//   activate <pid>             bring a process forward (what "show" needs)
//   sls-alpha <wid> <alpha>    SkyLight private: set another process's window alpha
//   sls-order-out <wid>        SkyLight private: order another process's window out
//   sls-level <wid> <level>    SkyLight private: set window level
import AppKit
import Foundation

typealias MainConn = @convention(c) () -> Int32
typealias SetAlpha = @convention(c) (Int32, UInt32, Float) -> Int32
typealias OrderWin = @convention(c) (Int32, UInt32, Int32, UInt32) -> Int32
typealias SetLevel = @convention(c) (Int32, UInt32, Int32) -> Int32
let sl = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight", RTLD_NOW)
func sym<T>(_ n: String, _: T.Type) -> T { unsafeBitCast(dlsym(sl, n)!, to: T.self) }

let a = CommandLine.arguments
switch a[1] {
case "front":
  print(NSWorkspace.shared.frontmostApplication?.processIdentifier ?? -1)
case "locked":
  let d = CGSessionCopyCurrentDictionary() as? [String: Any]
  print(d?["CGSSessionScreenIsLocked"] as? Int ?? 0)
case "activate":
  let app = NSRunningApplication(processIdentifier: pid_t(a[2])!)
  print(app?.activate(options: [.activateAllWindows]) ?? false)
case "sls-alpha":
  let cid = sym("SLSMainConnectionID", MainConn.self)()
  print(sym("SLSSetWindowAlpha", SetAlpha.self)(cid, UInt32(a[2])!, Float(a[3])!))
case "sls-order-out":
  let cid = sym("SLSMainConnectionID", MainConn.self)()
  print(sym("SLSOrderWindow", OrderWin.self)(cid, UInt32(a[2])!, 0, 0))
case "sls-level":
  let cid = sym("SLSMainConnectionID", MainConn.self)()
  print(sym("SLSSetWindowLevel", SetLevel.self)(cid, UInt32(a[2])!, Int32(a[3])!))
default:
  print("unknown")
}
