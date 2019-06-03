# realms-tool

### Dependencies
python 3.6+


### Mojang/Realms/Minecraft API notes
Login and logout are rate limited but clear up quite fast, less than a minute.


## Usage

```bash
usage: realms_client.py [-h] [--username USERNAME] [--email EMAIL]
                        [--password PASSWORD] [--latest-backup]
                        [--save-path SAVE_PATH] [--world-index WORLD_INDEX]
                        [--worlds]

Automation tool for Minecraft Realms.

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME
  --email EMAIL
  --password PASSWORD
  --latest-backup       Download latest backup.
  --save-path SAVE_PATH
                        Where to save latest backup.
  --world-index WORLD_INDEX
                        Index of world 1-4, defaults to 1
  --worlds              Print worlds' information.
```

### Examples

Print information about worlds
`./realms_client.py --username herobrine --email example@example.com --password hunter1 --worlds`
Download latest backup for world in slot 1 to current working directory
`./realms_client.py --username herobrine --email example@example.com --password hunter1 --latest-backup`
