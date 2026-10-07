# thresh

thresh is a devirtualiser for VMProtect-protected x64 binaries. the way it currently
works is that it lifts protected code into vtil using a custom made lifter. after
lifting, we will attempt to resolve the vm's dispatch chain and operations symbolically
and reduce the function back to its native logic that it was originally built from.

## How it works

thresh currently lifts blocks as it discovers them, once it reaches a computed
termination, the output result is mostly the vm itself - most devirtualisers will
attempt to associate an action to each handler in order to simplify it, the route thresh
decides to go is to peel away vm interference from the result in custom passes.

**Lifting** - as said before, `cfg/` will walk the native code into basic blocks as it's
discovered; `vtil/lift/` and `vtil/handlers/` will attempt to translate each instruction
into VTIL IL. anything that cannot be modeled are recorded instead.

**Forward state machine** - `vtil/forward/` carries a symbolic machine state through
each explored block, each block will have its image loads folded as well as any values
resolved at runtime. `pe/fake_mem/` is what we use to model TEB, PEB & process heap and
some runtime data that vmprotect queries - we do this so that vmprotect can expose
branches.

**Dispatch resolution** - `vtil/passes/indirect_jmp/` this file has quite a lot of work
to it, its main purpose is to resolve any indirect dispatching, vmprotect is riddled
with them, this file is the core to making this entire project work. it works out which
registers hold what vm information, these values consist of the virtual instruction
pointer or the rolling key used for connecting blocks, `vtil/vm_profile/` is also used
for this and pinning these values to blocks so that any symbolic trace, that we may
fallback to, doesn't fail.

**Reduction** - these are the several passes that we use, any that aren't listed but
existing are most likely legacy code:

| pass | what it does |
|---|---|
| `collapse_stack_check` | drops VMProtect's stack-relocation arms |
| `mark_exits` | converts leaf computed jumps into routine exits |
| `dead_stack` | removes stores to stack slots nothing ever reads |
| `fold_tamper_fork` | deletes branches whose only exit can never be a mapped address |
| `fold_redundant_fork` | folds conditionals whose arms do the same thing |

`fold_tamper_fork` is one that needs more than just a line. VMProtect scans its own
bytes for breakpoints and if it were to find one - will jmp somewhere that faults. this
clearly isn't native logic so we write a pass to identify these forks and fold them out
of the final representation. vtil cannot remove this natively because on paper, the
target is reachable because it has no concept of image memory. the pass works because we
can check the target against the image

## Sample

`GetVer_0` is a relatively small virtualised function within my test binary, its native
entry looks like this:

```asm
142de8: push rsi
142de9: push rdi
142dea: pushfq
142deb: movabs rdi, 0x68e15e577c244621
142df5: sub di, 0xefd
142dfa: mov qword ptr [rsp + 0x10], 0x2f77f3f9
142e03: mov rdi, qword ptr [rsp + 8]
142e08: call 0x180149d52
```

the `call` at the end is the vm entry. following it allows us to reach 24,557 native
instructions, which lift to 355,824 il instructions. after dispatch resolution and the
reduction passes, the whole routine is reduced to just six instructions:

```
0x142de8          jmp  0x18147c00373e41
0x18147c00373e41  jmp  0x180db800399284
0x180db800399284  ldd  t194806, $sp, 0x258
                  mov  rip, 0x2faf9c
                  mov  rax, 0xf9
                  vexit t194806
```

which is:

```c
return 0xF9;
```

## Layout

| path | |
|---|---|
| `src/cfg` | native control flow recovery |
| `src/pdb` | symbol and function lookup |
| `src/pe` | image parsing, fake environment memory, PE-aware tracer |
| `src/vtil/lift`, `src/vtil/handlers` | x64 to VTIL IL translation |
| `src/vtil/forward` | forward symbolic execution and reporting |
| `src/vtil/passes` | dispatch resolution and reduction passes |
| `src/vtil/vm_profile` | VM instance register layouts |

## Note

this is currently my entry project into both VTIL and devirtualisation so it's not
perfect - if you see any issues or something overcomplicated, open an issue or a pull
request or feel free to contact me at `dx9` on discord. this is still very work in
progress so expect bugs.

this requires a patch within `VTIL-SymEx/expressions/expression.cpp`, you can find the
issue i've opened at https://github.com/vtil-project/VTIL-Core/issues/84
