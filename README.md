# SafePath: Path Sanitizing

SafePath checks that pathnames are safe for use.

## Installation

SafePath can be installed with the `go get` command.

```shell
go get github.com/depp/safepath
```

## Usage

```go
import "github.com/depp/safepath"
```

To check if a filename, choose a combination of `Rules` flags and call the `CheckPathSegment()` function. For example, the `URLUnescaped` rule rejects any path which would require percent-encoding when used in a URL.

```go
rules := safepath.URLUnescaped
filename := "my_file.txt"
if err := rules.CheckPathSegment(filename); err != nil {
    return err
}
```

Relative paths can be checked with the `CheckPath()` function. Note that this function only recognizes the path separator /, it does not recognize \\.

```go
rules := safepath.URLUnescaped
filepath := "directory/my_file.txt"
if err := rules.CheckPathSegment(filepath); err != nil {
    return err
}
```

Error messages from this library are descriptive. Some examples:

```
Error: invalid path "/": path is absolute
Error: invalid path segment "NUL.TXT": uses reserved Windows filename "nul"
```

## Unicode

The notion of “safe” in Unicode is a bit difficult to define. This library does not have a comprehensive notion of safety for non-ASCII characters. Currently, there are only two rules that affect non-ASCII characters: `ValidUTF8` and `ASCIIOnly`.

## License

SafePath is provided under the MIT license. See LICENSE.txt for details.
