oleobj
======

oleobj is a script to extract embedded objects from OLE files.

Read-only extraction manifests are implemented in oletools.olemanifest.
Each reference binds the parent path, container member path, SHA-256
digest, and caller-supplied disclosure level. Identical payloads share one
blob, while disclosure stays attached to each reference. Malformed nested
OLE or zip members are marked unconfirmed with an unconfirmed_range.

It can be used either as a command-line tool, or as a python module from your own applications.

It is part of the [python-oletools](http://www.decalage.info/python/oletools) package.

## Usage

```text
TODO
```

--------------------------------------------------------------------------
    
## How to use oleobj in Python applications

See rtfobj.py source code.

TODO

--------------------------------------------------------------------------

python-oletools documentation
-----------------------------

- [[Home]]
- [[License]]
- [[Install]]
- [[Contribute]], Suggest Improvements or Report Issues
- Tools:
	- [[mraptor]]
	- [[msodde]]
	- [[olebrowse]]
	- [[oledir]]
	- [[oleid]]
	- [[olemap]]
	- [[olemeta]]
	- [[oleobj]]
	- [[oletimes]]
	- [[olevba]]
	- [[pyxswf]]
	- [[rtfobj]]
