# VSS (Volume Shadow Copy Service) for Windows 10

This tool may not work in future versions of Windows 10. Not all features are
working. Please let me know if you find one.

## Getting Started

Requirements:

* Windows 10 x64
* 64-bit Python 3.6 or above
* `pip install pywin32`

Run as administrator:

    python vss10.py vssadmin [arg]...

## Usage

`python vss10.py` is omitted from now on.

Create a shadow copy storage for drive C: under drive D: (size up to 10% of C:) 

    vssadmin Add ShadowStorage /For=C: /On=D: /MaxSize=10%

Create a snapshot of drive C:

    vssadmin Create Shadow /For=C:

Please refer to `vssadmin /?` for other usages.

`python vss10.py vssadmin` is slower than just `vssadmin`. For a batch operation 
run just `vssadmin` except for the first time.
