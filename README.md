# PyDns-parser

PyDns-parser is a dns parser written in python.This project arose as a need for scratching  my own itch when i was making
my  dns resolver.While building the resolver,i was constantly getting stuck making the query and due to that
problem,i figured out why not parse an actual dns query and figure out all of the parameters present and what do they
represent.Best,why not see them in diferent formats!!

This project allows you to see the dns query in :-
- hexadecimal format
- binary format
- decimal format
- Not only that ,you can specifcally find out the particular values of a dns query in all of these three formats
- It also creates a vertical representation of the entire dns query in all three formats

## Usage
```
python dnsparser.py -[format] -[parameter_name]
- binary -[parameter_name](E.g. id) : gives you the id in binary format
- hex    -[parameter_name]          : gives you the parameter in hexadecimal format
- dec    -[parameter_name]          : gives you the parameter in decimal format
- vertical -binary                  : gives you the entire query in vertical format in binary
- vertical -hex                     : gives you the entire query in vertical format in hexadecimal
- vertical -dec                     : gives you the entire query in vertical format in decimal
- all -binary                       : gives you the entire query in binary
- all -hex                          : gives you the entire query in hexadecimal
- all -dec                          : gives you the entire query in decimal
```
As for dnsclient, we have used dnslib to create the query.We then send it to our dnsparser who parses it thereafter.

## Getting started

- clone the repository ` git clone https://github.com/Saptarshi2001/PyDns-parser.git`
- on one terminal run  ` python dnsparser.py -[format] -[parameter_name]
- on another terminal run ` python dnsclient.py [whatever hostname you want to query]

## Contributing

-  This project is under development.Feel free to contribute to it.


