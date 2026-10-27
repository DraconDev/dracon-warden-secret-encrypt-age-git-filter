# Test-isolation negative control (raw, retained)

Executed BEFORE the private-HOME fix, on the then-current `integration_test.rs`.
No file other than the operator's live hooks directory was involved, and nothing
was committed manually.

```
$ sha256sum ~/.config/git/hooks/pre-push
1eaadcf344d11a194abf25ff8a368caf36df8d8779a33a0b9a5dd7eca47594ff  /home/dracon/.config/git/hooks/pre-push

$ timeout 600 cargo test -p dracon-warden --test integration_test --locked
...
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 34.23s

$ sha256sum ~/.config/git/hooks/pre-push
d122d8c10c2bec46b530043ed72fce104f0cf74926a71d1ee6d6a09b039919ec  /home/dracon/.config/git/hooks/pre-push
```

The suite passed while silently rewriting the operator's fleet-wide pre-push
hook. That is the leak: a green test run mutated live enforcement.

After the fix, the same command leaves the live hook byte-identical across a
full run (52.02s, 19 passed):

```
$ sha256sum /tmp/hook-before-leak-test2 ~/.config/git/hooks/pre-push
cc7caa7b71fb314e44dc2b512397aebe4883957b028d6e61b0638e3d8a3cb5fc  /tmp/hook-before-leak-test2
cc7caa7b71fb314e44dc2b512397aebe4883957b028d6e61b0638e3d8a3cb5fc  /home/dracon/.config/git/hooks/pre-push
```

`hook_refreshing_commands_never_touch_the_operator_home` now asserts this
directly, and also proves the refresh really happened inside the fixture HOME
(stale-body replacement) so the assertion cannot pass vacuously.
