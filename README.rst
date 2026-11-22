filetype.py |PyPI| |Pyversions| |API|
=====================================

Small and dependency free `Python`_ package to infer file type and MIME
type checking the `magic numbers`_ signature of a file or buffer.

This is a Python port from `filetype`_ Go package.

Features
--------

-  Simple and friendly API
-  Supports a `wide range`_ of file types
-  Provides file extension and MIME type inference
-  File discovery by extension or MIME type
-  File discovery by kind (image, video, audio…)
-  `Pluggable`_: add new custom type matchers
-  `Fast`_, even processing large files
-  Only first 261 bytes representing the max file header is required, so
   you can just `pass a list of bytes`_
-  Dependency free (just Python code, no C extensions, no libmagic
   bindings)
-  Cross-platform file recognition

Installation
------------

::

    pip install filetype

API
---

See `annotated API reference`_.

Examples
--------

Simple file type checking
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    import filetype

    def main():
        kind = filetype.guess('tests/fixtures/sample.jpg')
        if kind is None:
            print('Cannot guess file type!')
            return

        print('File extension: %s' % kind.extension)
        print('File MIME type: %s' % kind.mime)

    if __name__ == '__main__':
        main()

Capability manifests and offline audits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every matcher is a handler with a version.  ``filetype.capabilities()``
returns a manifest keyed by ``handler@version``:

.. code-block:: python

    import filetype

    manifest = filetype.capabilities()
    capability = manifest['Jpeg@1']
    print(capability.mime, capability.extension, capability.checkable)

The manifest keeps every handler, including formats that share a MIME type.
Use ``manifest.by_mime`` or ``manifest.lookup(mime=...)`` to see all of them.
Lifecycle metadata can be overridden when a handler is retired, disabled or
degraded:

.. code-block:: python

    manifest = filetype.capabilities(overrides={
        'Jpeg@1': {'available': False, 'status': 'retired'},
    })

Saved determinations can be checked for change impact without reading the
attachments again.  Pass the stored MIME/extension, the old handler version,
and optionally a small header sample or evidence captured at save time:

.. code-block:: python

    report = filetype.audit([
        {
            'handler': 'Jpeg',
            'version': 1,
            'mime': 'image/jpeg',
            'extension': 'jpg',
            'header': b'\xff\xd8\xff\xe0...',
        },
    ], capabilities=manifest)

    for result in report:
        print(result.status, result.checkable)

The audit never opens an attachment path.  When an available replacement
handler recognises a stored header as a different type, the result is marked
``changed`` and keeps both the previous and current evidence.  A retired or
disabled handler yields ``degraded`` with ``checkable=False``; a MIME that maps
to several formats without a dispatch hint yields ``ambiguous``.  Ledgers that
already carry both ``previous`` and ``current`` records are accepted as well.
If the old ledger claimed a format was checkable but the deployed handler is
retired, the result also sets ``stale=True``.

The same operations are available from the command line.  ``--capabilities``
prints the manifest as JSON, while ``--audit`` reads a saved JSON ledger:

.. code-block:: shell

    filetype --capabilities > capabilities.json
    filetype --audit ledger.json --manifest capabilities.json

Supported types
---------------

Image
^^^^^

-  **dwg** - ``image/vnd.dwg``
-  **xcf** - ``image/x-xcf``
-  **jpg** - ``image/jpeg``
-  **jpx** - ``image/jpx``
-  **jxl** - ``image/jxl``
-  **png** - ``image/png``
-  **apng** - ``image/apng``
-  **gif** - ``image/gif``
-  **webp** - ``image/webp``
-  **cr2** - ``image/x-canon-cr2``
-  **tif** - ``image/tiff``
-  **bmp** - ``image/bmp``
-  **jxr** - ``image/vnd.ms-photo``
-  **psd** - ``image/vnd.adobe.photoshop``
-  **ico** - ``image/x-icon``
-  **heic** - ``image/heic``
-  **avif** - ``image/avif``
-  **qoi** - ``image/qoi``
-  **dds** - ``image/dds``

Video
^^^^^

-  **3gp** - ``video/3gpp``
-  **mp4** - ``video/mp4``
-  **m4v** - ``video/x-m4v``
-  **mkv** - ``video/x-matroska``
-  **webm** - ``video/webm``
-  **mov** - ``video/quicktime``
-  **avi** - ``video/x-msvideo``
-  **wmv** - ``video/x-ms-wmv``
-  **mpg** - ``video/mpeg``
-  **flv** - ``video/x-flv``

Audio
^^^^^

-  **aac** - ``audio/aac``
-  **mid** - ``audio/midi``
-  **mp3** - ``audio/mpeg``
-  **m4a** - ``audio/mp4``
-  **ogg** - ``audio/ogg``
-  **flac** - ``audio/x-flac``
-  **wav** - ``audio/x-wav``
-  **amr** - ``audio/amr``
-  **aiff** - ``audio/x-aiff``

Archive
^^^^^^^

-  **br** - ``application/x-brotli``
-  **rpm** - ``application/x-rpm``
-  **dcm** - ``application/dicom``
-  **epub** - ``application/epub+zip``
-  **zip** - ``application/zip``
-  **tar** - ``application/x-tar``
-  **rar** - ``application/x-rar-compressed``
-  **gz** - ``application/gzip``
-  **bz2** - ``application/x-bzip2``
-  **7z** - ``application/x-7z-compressed``
-  **xz** - ``application/x-xz``
-  **pdf** - ``application/pdf``
-  **exe** - ``application/x-msdownload``
-  **swf** - ``application/x-shockwave-flash``
-  **rtf** - ``application/rtf``
-  **eot** - ``application/octet-stream``
-  **ps** - ``application/postscript``
-  **sqlite** - ``application/x-sqlite3``
-  **nes** - ``application/x-nintendo-nes-rom``
-  **crx** - ``application/x-google-chrome-extension``
-  **cab** - ``application/vnd.ms-cab-compressed``
-  **deb** - ``application/x-deb``
-  **ar** - ``application/x-unix-archive``
-  **Z** - ``application/x-compress``
-  **lzo** - ``application/x-lzop``
-  **lz** - ``application/x-lzip``
-  **lz4** - ``application/x-lz4``
-  **zstd** - ``application/zstd``

Document
^^^^^^^^

-  **doc** - ``application/msword``
-  **docx** - ``application/vnd.openxmlformats-officedocument.wordprocessingml.document``
-  **odt** - ``application/vnd.oasis.opendocument.text``
-  **xls** - ``application/vnd.ms-excel``
-  **xlsx** - ``application/vnd.openxmlformats-officedocument.spreadsheetml.sheet``
-  **ods** - ``application/vnd.oasis.opendocument.spreadsheet``
-  **ppt** - ``application/vnd.ms-powerpoint``
-  **pptx** - ``application/vnd.openxmlformats-officedocument.presentationml.presentation``
-  **odp** - ``application/vnd.oasis.opendocument.presentation``

Font
^^^^

-  **woff** - ``application/font-woff``
-  **woff2** - ``application/font-woff``
-  **ttf** - ``application/font-sfnt``
-  **otf** - ``application/font-sfnt``

Application
^^^^^^^^^^^

-  **wasm** - ``application/wasm``

.. _Python: http://python.org
.. _magic numbers: https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files
.. _filetype: https://github.com/h2non/filetype
.. _wide range: #supported-types
.. _Pluggable: #add-additional-file-type-matchers
.. _Fast: #benchmarks
.. _pass a list of bytes: #file-header
.. _annotated API reference: https://h2non.github.io/filetype.py/

.. |PyPI| image:: https://img.shields.io/pypi/v/filetype.svg?maxAge=2592000?style=flat-square
   :target: https://pypi.python.org/pypi/filetype
.. |Pyversions| image:: https://img.shields.io/pypi/pyversions/filetype.svg?style=flat-square
    :target: https://pypi.python.org/pypi/filetype
.. |API| image:: https://img.shields.io/badge/api-docs-green.svg
   :target: https://h2non.github.io/filetype.py
