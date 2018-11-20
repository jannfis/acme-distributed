# Things acme-distributed still needs

## Functionality

- Implement DNS challenges
- Group servers for mapping certain certificates to certain challenge servers
- ACME account management (new/modify/delete account)

## Cosmetics

- Increase comment-to-code ration

## Packaging

- Put code in separate files instead of one monolithic script
- Create & publish a Ruby gem

## Known bugs

- Under some circumstances, old challenge files can remain on your web server(s)
- Error handling is insufficient
