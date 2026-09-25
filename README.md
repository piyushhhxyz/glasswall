# Glasswaller

**See everything. Touch nothing.**

Source on the left, what the pipeline produced on the right. Eyeball a hundred
documents in a sitting without touching the mouse.

Glasswaller is read-only by construction. It opens an export and its redacted
counterpart side by side, pairs the files up, and shows you what changed. It
never writes to the locations it reads.

## Run it

```
cd ~/Desktop/glasswaller
./glasswaller
```

A popup asks where the run is. Give it **one** location — a folder, a zip, or
anything that names an S3 location — and it works out which half is the source
and which is the output. Ctrl-C to stop.

For S3, paste whatever you have. The console URL out of the address bar, either
REST endpoint, an ARN, or the `s3://` URI all work, and the region comes off the
URL when it is there. Pasting a location inside `_pii/output/` opens the run
that output belongs to, so both halves are there to compare.

Skip the popup:

```
./glasswaller ~/Downloads/some-export
./glasswaller s3://bucket/export --profile sail
./glasswaller 'https://s3.console.aws.amazon.com/s3/buckets/bkt?region=ap-south-1&prefix=_pii/output/' --profile sail
```

Quote a console URL — the `&` will otherwise background your shell.

## Several at once

Give more than one location, or repeat `--pair`, and each opens in its own
tab on its own port. Verdicts are keyed by the pair of locations, so the tabs
never overwrite each other.

```
./glasswaller ~/Downloads/run-a ~/Downloads/run-b ~/Downloads/run-c

./glasswaller --profile sail \
  --pair s3://bkt/export s3://bkt/export-pii \
  --pair s3://bkt/export/unit-a s3://bkt/export-pii/unit-a
```

Use `--pair` when the two halves are siblings rather than nested. Ctrl-C stops
all of them.

## S3: getting in

Every S3 location needs `--profile`. Which one depends on who owns the bucket —
a client bucket is usually a different AWS account from your own, and your SSO
login does not reach it. Two ways in.

**SSO, for accounts on your own start URL:**

```
aws sso login --profile sail
./glasswaller s3://bucket/prefix --profile sail
```

To see which accounts that login actually covers — buckets outside them will
fail no matter how many times you re-login:

```
aws sso list-accounts --region us-west-2 --access-token \
  "$(jq -r 'select(.accessToken)|.accessToken' ~/.aws/sso/cache/*.json | head -1)"
```

Add a profile per account to `~/.aws/config`:

```ini
[profile some-client]
sso_session    = sail
sso_account_id = 111122223333
sso_role_name  = SomeRole
region         = ap-south-1
```

**Access keys, for a client account you were handed credentials for.**
Put them in `~/.aws/credentials` — never in a command, a script, or this repo:

```ini
[some-client]
aws_access_key_id     = AKIA...
aws_secret_access_key = ...
```

```
chmod 600 ~/.aws/credentials
aws sts get-caller-identity --profile some-client    # confirms which account
./glasswaller s3://client-bucket/their-export --profile some-client
```

**If it will not open**, run the listing by hand — the error names the missing
permission, and `AccessDenied` on `s3:ListBucket` is not something this tool
can work around:

```
aws s3 ls s3://bucket/prefix/ --profile some-client
```

Listing is what builds the index, so read access alone is not enough. Ask for
`s3:ListBucket` and `s3:GetObject` on that bucket, or for credentials in the
account that owns it.

Python 3.9+, standard library only. Nothing is installed. PDFs scroll in step
if PyMuPDF is importable by any interpreter on the box; without it they fall
back to the browser's viewer.

## Use it

`j` / `k` move between files, `→` / `←` between folders. Press `r` when a
document is clean, `c` to leave a comment, `f`-worthy findings go in the
comment. `?` lists every key in the app.

Anything on the right still showing a person's name, address, DOB, SSN or
personal mobile is a leak. So is the opposite: a toll-free number, a column
heading or a product name that got scrubbed. A right pane identical to the
left means the redaction never ran; a blank one means it broke.

The search box covers **every** pair in the run, not just your share. Type a
path a teammate reported and it opens, whether or not it was dealt to you;
hits from outside your sample are tinted and review exactly like the rest.

Press `n`, or **Folder-names**, for what the pipeline did to the folder names
themselves. A folder is part of the deliverable too:
`gmail/anirudh.trivedi@inc42.com/messages/page_000001.jsonl` names a person and
their employer in the object key however clean the two panes look, and neither
pane shows it. The panel is one table — every folder, its name in the source, its name in the
output — searchable. A name the output kept that reads as personal data is
tinted. The folder each document sits in is also printed above its pane,
source against output.

Two people on the same run get different files. The sample is seeded on a salt
kept in `~/.glasswaller-salt`, written once per machine — so your files stay the
same across refreshes and re-clones, and your colleague's hundred is a
different hundred. On one real export two reviewers covered 631 files between
them instead of 340.

To review exactly what someone else is reviewing, pass their sample id (it is
printed on startup and shown in the header):

```
./glasswaller --pair SRC OUT --profile sail --seed 256028
```

Press `m`, or the **PII-mappings** button, for the run's substitution table:
every attribute type down the side with its real count, the exact rows in the
middle, paged. Nothing is sampled away — every original the pipeline found,
what it replaced it with, and the ones it found and left alone. Search spans
every type, and you can leave a comment on any row. It is picked up from
`_pii/pii_mappings.db` beside the output if the run shipped one, otherwise
point at it — either on the command line or in the panel itself, which asks
when the run shipped none:

```
./glasswaller --pair SRC OUT --profile sail --mappings ~/runs/_pii/pii_mappings.db
./glasswaller --pair SRC OUT --profile sail --mappings s3://bucket/run/_pii/pii_mappings.db
```

Verdicts save to `marks.json` as you go, keyed by the pair of locations, so
closing the tab and coming back tomorrow resumes where you stopped.

Pull out everything you commented on:

```
python3 -c "import json;m=json.load(open('marks.json'));\
[print(k,'|',c) for s,v in m.items() for k,d in v.items() for c in d.get('comments',[])]"
```
