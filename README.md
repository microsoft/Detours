# CoreHook Windows Hooking Module

For [CoreHook](https://github.com/unknownv2/CoreHook), the [Microsoft Detours](https://github.com/Microsoft/Detours) package serves as a good binary hooking module since it supports x86, x86_64, ARM, and ARM64, while [EasyHook](https://github.com/EasyHook/EasyHook) only supports x86 and x86_64. Since .NET Core supports the two ARM architectures, we can implement the necessary changes to support those architectures.

## Supported Platforms

`X86, X64, and ARM` have all been tested and work, but I do not have a *Windows on ARM* device to test `ARM64` support with. If you have one to loan, let me know, otherwise, I will wait for a price drop.

## Building

Building the DLL requires Visual Studio and nmake (it has been tested with `Visual Studio 2017` only). You can find the build environments for your Visual Studio installation normally at `C:\Program Files (x86)\Microsoft Visual Studio\2017\[ProductType]\VC\Auxiliary\Build`, where `[ProductType]` is your version of Visual Studio: **(Community, Professional, or Enterprise)**.

### X86
* Start the `vcvars32.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:
 ```
 nmake DETOURS_TARGET_PROCESSOR=X86
 ```
### X64 
* For X64, start the `vcvars64.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:

 ```
 nmake DETOURS_TARGET_PROCESSOR=X64
 ```

### ARM

* For ARM, start the `vcvarsx86_arm.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:

 ```
 nmake DETOURS_TARGET_PROCESSOR=ARM
 ```

 ### ARM64 (Unsupported, for future reference)
* For ARM64, start the `vcvarsamd64_arm64.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:
 ```
 nmake DETOURS_TARGET_PROCESSOR=ARM64
 ```

## Installing

* For X86, the output directory is `bin.X86` and the output file is `corehook32.dll`.
* For X64, the output directory is `bin.X64` and the output file is `corehook64.dll`.
* For ARM, the output directory is `bin.ARM` and the output file is `corehook32.dll`.
* For ARM64, the output directory is `bin.ARM64` and the output file is `corehook64.dll`.

Copy the desired file for your target architecture to the output directory of the program that uses [CoreHook](https://github.com/unknownv2/CoreHook/).

## Notes

Since `CoreHook` is based on `EasyHook`, the `corehook` DLL implements the required subset of exports that [EasyHook](https://github.com/EasyHook/EasyHook) implements for hooking to work properly, so you can swap out the `corehook` DLL with the native `easyhook` DLL on the X86 and X64 architectures if you want to use that one instead. 

For example, on X64, you can copy the `EasyHook64.dll` to the output directory of your program and rename it to `corehook64.dll` and `CoreHook` will function as expected.  