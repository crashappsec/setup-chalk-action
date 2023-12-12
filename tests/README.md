# Tests

For now these are just sanity checks which allow to run `setup.sh`
script within an isolated container in either Ubuntu/Alpine.

Default runs:

```sh
make ubuntu all
make alpine all
```

With debug logs:

```sh
make prefix DEBUG=true
```

To copy existing `chalk` from local chalk repo located next to this repo
instead of downloading `chalk` from official release:

```sh
make prefix COPY=true
```
