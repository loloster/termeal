usage: termeal.py [-h] [-x XCOL] [-y YCOL] [-f FILTER] [-c COLOR]
                  [-d {colors,ports}] [-epi EPHEMERALPORTMIN]
                  [-epa EPHEMERALPORTMAX]
                  interface

A Scanner Interface Darkly

positional arguments:
  interface             interface to scan

optional arguments:
  -h, --help            show this help message and exit
  -x XCOL, --xcol XCOL  number of columns (8 by default)
  -y YCOL, --ycol YCOL  number of rows (8 by default)
  -f FILTER, --filter FILTER
                        tcpdump filter
  -c COLOR, --color COLOR
                        number of color
  -d {colors,ports}, --display {colors,ports}
                        type of side display
  -epi EPHEMERALPORTMIN, --ephemeralportmin EPHEMERALPORTMIN
                        ephemeral port min to exclude (32768 by default), set
                        to 65536 to include all ports
  -epa EPHEMERALPORTMAX, --ephemeralportmax EPHEMERALPORTMAX
                        ephemeral port max to exclude (61000 by default)
