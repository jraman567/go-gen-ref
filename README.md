# go-gen-ref
## Introduction
This tool generates reference values formatted as CoRIM; it presently supports SEV-SNP. It is suitable for a Cloud Service Provider (CSP) that wishes to generate reference values for their TEE shapes. It is similar to the [gen-corim](https://github.com/veraison/gen-corim), and we can merge both.

## SEV-SNP reference values
This tool formats SEV-SNP evidence into CoRIM as specified by its [profile](https://datatracker.ietf.org/doc/draft-deeglaze-amd-sev-snp-corim-profile/).

In this case, the reference values are a function of the number of vcpus in the TEE. As such, there would be as many reference values as vcpus. We could optimize it by factoring the shared values, but a [missing feature](https://github.com/veraison/services/issues/298) is blocking this.

The SEV-SNP sub-command needs a vmconfig file describing the target TEE shape. Please see ```sample/sevsnp/vmconfig.yaml``` for an example.

## Usage
The command format is as follows:
```sh
go-gen-ref <scheme> <scheme-options>
```
| Command | Description |
| ------ | ------ |
| sevsnp | refvals for SEV-SNP |

```sh
./go-gen-ref sevsnp -r sample/sevsnp/report.bin -c sample/sevsnp/vmconfig.yaml -o sample/sevsnp/OVMF_CODE.cc.fd -f /tmp/corim.cbor
```
| Option | Description |
| ------ | ------ |
| -r | The SEV-SNP attestation report in binary format |
| -c | vmconfig file |
| -o | The OVMF binary used to deploy the TEE |
| -f | specifies the name of output CoRIM file; if unspecified, the tool picks a random name |

In the above example, the output will be in /tmp/corim.cbor.

## License

Apache 2.0
