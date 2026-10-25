/*
 * Frida runtime hook template.
 *
 * Replace moduleName, exportName, and the return value before running.
 *
 *   frida -f target.exe -l frida_hook_template.js --no-pause
 *   frida -n target.exe -l frida_hook_template.js
 */

const moduleName = "target.dll";
const exportName = "TargetFunction";
const replacementReturn = 1;

function log(...args) {
  console.log("[phxre]", ...args);
}

function main() {
  const module = Process.getModuleByName(moduleName);
  if (!module) {
    log("module not found:", moduleName);
    return;
  }

  const address = module.getExportByName(exportName);
  if (!address) {
    log("export not found:", exportName);
    return;
  }

  log("hooking", moduleName + "!" + exportName, "at", address);

  Interceptor.attach(address, {
    onEnter(args) {
      this.args = [];
      for (let index = 0; index < 6; index += 1) {
        this.args.push(args[index]);
      }
      log("enter", this.args.map((value) => value.toString()).join(", "));
    },
    onLeave(retval) {
      log("leave original:", retval);
      retval.replace(ptr(replacementReturn));
      log("leave replaced:", retval);
    },
  });
}

setImmediate(main);
