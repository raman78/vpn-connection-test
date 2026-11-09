"""vpn-connection-test: compare direct and VPN network paths."""

try:
    from ._version import __version__
except ImportError:           # a source checkout that was never built or installed
    __version__ = "0+unknown"
