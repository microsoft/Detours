# CoreHook Windows Hooking Module

For [CoreHook](https://github.com/unknownv2/CoreHook), the [Microsoft Detours](https://github.com/Microsoft/Detours) package serves as a good binary hooking module since it supports x86, x86_64, ARM, and ARM64, while [EasyHook](https://github.com/EasyHook/EasyHook) only supports x86 and x86_64. Since .NET Core supports the two ARM architectures, we can implement the necessary changes to support those architectures for CoreHook.

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


## Original Licenses

### [Microsoft Detours](https://github.com/Microsoft/Detours)
```
# Copyright (c) Microsoft Corporation

All rights reserved.

# MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### [EasyHook](https://github.com/EasyHook/EasyHook)

```
Copyright (c) 2009 Christoph Husse & Copyright (c) 2012 Justin Stenning

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```