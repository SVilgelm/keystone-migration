# keystone-migration
[![Build Status](https://travis-ci.org/SVilgelm/keystone-migration.svg?branch=master)](https://travis-ci.org/SVilgelm/keystone-migration)

A migration tool for keystone objects from one cloud to another using api v3

# Usage
***Dry run***
```
$ ./main.py config.ini
Domains:
  - test4 (38384f4aa7684d078f687bd5068b85a4)
Projects (Domain/Name):
  - test4/pr3 (ef9655332e68422a9819a0b3d84bba94)
  - test1/pr1 (b4c822500c4e4dd0b51aa98e727795d2)
  - test1/pr2 (bdf347b16dab41ad88d4fc18606e96a0)
Users (Domain/Name[:new password]):
  - test1/user4 (3d62a10e97c64570a1b7145bdf76e0f6)
  - test4/user3 (46f03bb586784c958eb4eb7bcf73e48f)
Role assignments for a user on a domain (Domain/User/Role):
  - test1/user1/r1 (047292eb5cb0434ea22fadb238c84c4d)
Role assignments for a user on a project (Domain/Project/User/Role):
  - test4/pr3/user3/r1 (047292eb5cb0434ea22fadb238c84c4d)
  - test1/pr2/user1/r1 (047292eb5cb0434ea22fadb238c84c4d)
```

***Migration***
```
$ ./main.py config.ini --migrate
The following objects have been successfully migrated:
Projects (Domain/Name):
  - test1/pr2 (bdf347b16dab41ad88d4fc18606e96a0)
Users (Domain/Name[:new password]):
  - test1/user4:sT9MsyduXsHwWc18JbiN (3d62a10e97c64570a1b7145bdf76e0f6)
The following objects are not migrated:
Domains:
  - test4 (38384f4aa7684d078f687bd5068b85a4)
Projects (Domain/Name):
  - test4/pr3 (ef9655332e68422a9819a0b3d84bba94)
Users (Domain/Name[:new password]):
  - test4/user3 (46f03bb586784c958eb4eb7bcf73e48f)
```
