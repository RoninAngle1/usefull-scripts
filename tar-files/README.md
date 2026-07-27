# Archive Files by Date

A lightweight Bash utility that compresses every regular file in the current directory into individual `tar.gz` archives with the current date appended to the filename, then removes the original files after successful archiving.

This script is useful for log rotation, backup automation, temporary file cleanup, and scheduled archival tasks.

---

# Features

- Compresses every regular file in the current directory
- Creates one archive per file
- Automatically appends today's date to the archive filename
- Removes the original file only after a successful archive
- Skips directories
- Skips files that are already `.tar.gz` archives
- Simple, dependency-free implementation
- Safe execution with strict Bash error handling

---

# How It Works

For every regular file in the current working directory, the script:

1. Checks whether the item is a regular file.
2. Ignores directories.
3. Skips files that already end with `.tar.gz`.
4. Creates a compressed archive named:

```
<filename>-YYYY-MM-DD.tar.gz
```

5. Removes the original file if archiving succeeds.
6. Prints the operation status.

---

# Requirements

## Operating System

- Linux
- macOS
- Unix-like systems

---

## Required Software

The following utilities must be installed:

- Bash
- tar
- date

These tools are available by default on most Linux distributions.

---

# Script Behavior

Input directory:

```
Current Working Directory
```

Output:

One compressed archive for every regular file.

Example:

Before execution:

```
logs.txt
backup.sql
report.csv
image.png
archive.tar.gz
documents/
```

After execution:

```
logs.txt-2026-07-27.tar.gz
backup.sql-2026-07-27.tar.gz
report.csv-2026-07-27.tar.gz
image.png-2026-07-27.tar.gz
archive.tar.gz
documents/
```

The original files are removed after successful compression.

---

# File Naming

Archive format:

```
<original_filename>-YYYY-MM-DD.tar.gz
```

Examples:

```
database.sql
```

becomes

```
database.sql-2026-07-27.tar.gz
```

---

```
access.log
```

becomes

```
access.log-2026-07-27.tar.gz
```

---

# Usage

Make the script executable:

```bash
chmod +x archive-files.sh
```

Run the script:

```bash
./archive-files.sh
```

Or specify the Bash interpreter explicitly:

```bash
bash archive-files.sh
```

---

# Example

Initial directory:

```
$ ls

notes.txt
backup.sql
report.csv
old.tar.gz
images/
```

Execute:

```bash
./archive-files.sh
```

Output:

```
Archived and removed: notes.txt -> notes.txt-2026-07-27.tar.gz
Archived and removed: backup.sql -> backup.sql-2026-07-27.tar.gz
Archived and removed: report.csv -> report.csv-2026-07-27.tar.gz
```

Final directory:

```
notes.txt-2026-07-27.tar.gz
backup.sql-2026-07-27.tar.gz
report.csv-2026-07-27.tar.gz
old.tar.gz
images/
```

---

# Error Handling

The script uses strict Bash options:

```bash
set -euo pipefail
```

This enables:

- Exit immediately on command failures (`-e`)
- Treat unset variables as errors (`-u`)
- Detect failures inside pipelines (`pipefail`)

If archiving a file fails:

- The original file is preserved.
- An error message is printed.

Example:

```
Failed to archive: database.sql
```

---

# Exit Codes

| Exit Code | Description |
|-----------|-------------|
| 0 | Script completed successfully |
| Non-zero | Unexpected execution error |

---

# Notes

- The script operates only on the current working directory.
- It does not search subdirectories recursively.
- Existing `.tar.gz` archives are never modified.
- File permissions and timestamps are preserved by `tar`.
- Hidden files (for example, `.env` or `.gitignore`) are also archived because shell globbing includes them only if explicitly configured; by default, `*` does **not** match hidden files in Bash.

---

# Limitations

- Non-recursive
- No overwrite protection if an archive with the same name already exists
- Uses the current system date
- Processes files sequentially
- Does not verify available disk space before creating archives

---

# Customization

## Archive Another Directory

Instead of running inside the target directory:

```bash
cd /path/to/files
./archive-files.sh
```

you can modify the script to iterate over another directory.

---

## Keep Original Files

Remove or comment out:

```bash
rm -f -- "$file"
```

The script will then archive files without deleting the originals.

---

## Include Subdirectories

Replace the file loop with a recursive search using `find`:

```bash
find . -type f
```

---

## Change Archive Format

Use gzip (current):

```
.tar.gz
```

or modify the `tar` command to use another compression method, such as:

- `.tar.xz`
- `.tar.bz2`
- `.zip`

---

# Use Cases

- Daily log archival
- Backup rotation
- Temporary file cleanup
- Scheduled cron jobs
- CI/CD artifact packaging
- Database dump archival
- Report archival
- File retention automation

---

# Example Cron Job

Run every day at midnight:

```cron
0 0 * * * /path/to/archive-files.sh
```

---

# Security Considerations

- Ensure sufficient disk space before execution.
- Verify write permissions in the target directory.
- Test the script on sample files before using it in production.
- Consider copying archives to external storage after creation.

---

# Future Enhancements

Potential improvements include:

- Recursive directory support
- Configurable destination directory
- Parallel compression
- Archive verification after creation
- Compression level selection
- Include/exclude patterns
- Dry-run mode
- Logging to a file
- Progress indicator
- Automatic deletion based on retention policy
- Email notifications
- Checksum generation
- Restore helper script

---

# License

Internal Use

Modify and distribute according to your organization's policies.
