# dlsub

A tool (x86-64 only) for replacing a subset of functions in dynamic libraries.

Let's say you're meddling around with a program that uses
[SDL](https://libsdl.org).  One thing you might want to do is replace an SDL
function (e.g. `SDL_SetWindowTitle`) with your own function so you have control
over it (e.g. you can set your own special window title).

This is possible on most operating systems. On Unix-like systems, you can use
the `LD_LIBRARY_PATH` environment variable to fool an application into using
your own dynamic library instead of the dynamic library it was intending to use.
On Windows, you can create a DLL in the same directory as the executable with
the same name as the one you want to replace. But the issue with this is you
probably only want to replace a few functions, and you still want access to the
original library functions (e.g. the *real* `SDL_SetWindowTitle`). This is where
dlsub comes in.

## Dependencies

You will need:

- [nasm](https://nasm.us)
- a C compiler

To install these on Ubuntu/Debian:

```bash
sudo apt install nasm tcc
```

On Windows, you can get yourself a copy of Microsoft Visual Studio, search for
a file called `vcvarsall.bat`, add it to your PATH, and the run `vcvarsall x64`
to set up the C compiler. You can install NASM from their website, and to make
things more convenient, you can add nasm.exe to your PATH (or just copy
the file to the same directory as dlsub.exe).

On Unix-like systems, the default is to use TCC (for faster preprocessing and
less likelihood of weird syntax messing dlsub up). You can, however, override
this by setting the C_PREPROCESSOR environment variable.

## Compiling dlsub

You can use the `Makefile` and `make.bat` provided, or you can just compile
`main.c` with any C compiler.

## Figuring out which library file is being used

On Windows, it may just be a DLL file in the same directory as the exe.
Otherwise, you can install [depends.exe](https://www.dependencywalker.com/)
to figure it out.

On Unix-like systems, if you want to know what specific library files an
executable is using, run:

```bash
ldd <name of executable>
```

## Usage

The standard usage of dlsub is:

```bash
dlsub -I <library include directory> -i <library header file> -l <library file> -o <output name>
```

You can see `dlsub --help` for a list of all options.

You can specify multiple header files if the library has more than one.
Here is an example invocation for replacing SDL:

Windows:

```bash
dlsub --no-warn -l C:\SDL2-2.0.14\lib\x64\SDL2.dll -I C:\SDL2-2.0.14\include -i SDL.h -i SDL_syswm.h -i SDL_vulkan.h -C /DSDL_DISABLE_IMMINTRIN_H -o sdl
```

Linux:

```bash
./dlsub --no-warn -l /lib/x86_64-linux-gnu/libSDL2-2.0.so -I /usr/include/SDL2 -i SDL.h -i SDL_syswm.h -i SDL_vulkan.h -C -DSDL_DISABLE_IMMINTRIN_H -o sdl
```

(the `-DSDL_DISABLE_IMMINTRIN_H` is needed for tcc, and it also speeds up
processing)

You should now get a file called `sdl.c` and another one called `sdl.asm`.
Now let's say you want to replace `SDL_SetWindowTitle`. First, delete the line
in `sdl.asm`:

```
GLOBAL SDL_SetWindowTitle
```

(This deletes the default replacement, i.e. to redirect to the real SDL
function).

(This is specific to SDL.h on Windows)
At the start of sdl.c, add:

```c
#define DLL_EXPORT
```

Now at the end of sdl.c, add:

```c
DLSUB_EXPORT void SDL_SetWindowTitle(SDL_Window *window, const char *title) {
	REAL_SDL_SetWindowTitle(window, "substitute title");
}
```

The `DLSUB_EXPORT` ensures that the function is exported out to the dynamic
library (on Windows, where that distinction is made).

On Linux, you can now compile libSDL2-2.0.so.0 with:

```
nasm -f elf64 sdl.asm
cc -fPIC -shared sdl.o sdl.c -o libSDL2-2.0.so.0 -I/usr/include/SDL2
```

And run a program that uses SDL like this:
```
LD_LIBRARY_PATH=/directory/where/your/library/file/is ./some_application
```

And on Windows:

```
nasm -f win64 sdl.asm -o sdl_asm.obj
cl /nologo /Fe:SDL2 /LD sdl_asm.obj sdl.c /I C:\\SDL2-2.0.14\\include
```

And just copy `SDL2.dll` to the same directory as the target application.

Note that dlsub *cannot* handle dynamic libraries' objects (e.g.
`extern int foo;`), so if there are any you will have to make your own
substitutes for those.

## What's with the assembly file?

dlsub needs `nasm` in order to work. This is partly because of varargs
functions: In C, there's no way of redirecting one varargs
function to another.

Also, if for whatever reason there's a function in the dynamic library
that's not defined in any header file, it would be impossible to keep it working
without assembly.

## More examples...

### (Unix-y) Replacing `XNextEvent` from libX11

```bash
dlsub --no-warn -l /usr/lib/x86_64-linux-gnu/libX11.so.6 -I /usr/include/X11 -i Xlib.h -i Xutil.h -o x11
```

Delete the line from x11.asm:

```
GLOBAL XNextEvent
```

Add to the bottom of x11.c:

```c
/* let's hope nobody needs to use these */
void *_XCreateMutex_fn, *_XFreeMutex_fn, *_XLockMutex_fn,
	*_XUnlockMutex_fn, *_Xglobal_lock;

int XNextEvent(Display *dpy, XEvent *event) {
	int ret = REAL_XNextEvent(dpy, event);
	/* 
	change all key events to pressing "v"
	(may be a different key for non-QWERTY keyboards)
	*/
	if (event->type == KeyPress || event->type == KeyRelease)
		event->xkey.keycode = 55;
	return ret;
}
```

```bash
nasm -f elf64 x11.asm
cc -fPIC -shared x11.c x11.o -o libX11.so.6 -I/usr/include/X11
```

### (Unix-y) Replacing `exp` from libm

Here's a silly example. This could cause some... interesting behavior.

Note that because of glibc name-mangling you can only replace *some* libm
functions.

```bash
dlsub --no-warn -l /lib/x86_64-linux-gnu/libm.so.6 -I /usr/include -i math.h -o math
```

Delete from math.asm:

```
GLOBAL exp
```

Add to math.c:

```
double exp(double x) {
	return 2.0 * x;
}
```

```
nasm -f elf64 math.asm
cc -fPIC -shared math.c math.o -o libm.so.6
```

### Report a bug

Bugs can be sent to `pommicket at pommicket.com`. Please only report bugs that
could/do actually occur in real usage of dlsub; in theory, it might not
correctly parse a function returning a function pointer that returns a function
pointer but that doesn't happen in real libraries.
