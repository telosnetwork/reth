# telos-reth

## Rebase notes:
```bash
git checkout main
git fetch upstream
git rebase <SHA OF UPSTREAM RELEASE TAG>
git push
git checkout telos-main
#squash all commits into 1 if needed, find the previously squashed commit, the first Telos commit after the upstream commit and use it below
git rebase -i <FULL COMMIT SHA FOR FIRST TELOS COMMIT HERE>^
git rebase main # this is where it might get tricky! :)
```

## Clearing out freelist:

`mdbx_copy -c $OLD $NEW`

Per this: https://reth.rs/run/troubleshooting.html#compact-the-database
