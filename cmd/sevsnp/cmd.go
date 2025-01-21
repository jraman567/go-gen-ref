package sevsnp

import (
	"fmt"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/veraison/corim/corim"
)

const (
	ClassIDByChip = "1.3.6.1.4.1.3704.3.1"
	ClassIDByCsp  = "1.3.6.1.4.1.3704.3.2"
	ProfileName   = "http://amd.com/2024/snp-corim-profile"
)

var (
	vmConfigFile *string
	ovmfFile     *string
	reportFile   *string
	corimFile    *string
)

var (
	reportProto *sevsnp.Report
	Cmd         = NewSevsnpCmd(afero.NewOsFs())
)

func NewSevsnpCmd(fs afero.Fs) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sevsnp",
		Short: "Generate SEV-SNP reference values",
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.SetConfigFile(*vmConfigFile)
			err := viper.ReadInConfig()
			if err != nil {
				fmt.Printf("Error reading config file, %s", err)
				return nil
			}

			_, _ = fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())

			report, err := afero.ReadFile(fs, *reportFile)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, "Failed to read report file:", err)
				return nil
			}

			reportProto, err = abi.ReportToProto(report)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				return nil
			}

			_, _ = fmt.Fprintf(os.Stderr, "Report file successfully read: %d bytes\n", len(report))

			err = composeRefVals(fs)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				return nil
			}

			return nil
		},
	}

	vmConfigFile = cmd.Flags().StringP(
		"vmconfig", "c", "", "YAML file containing info about VM/TEE",
	)

	ovmfFile = cmd.Flags().StringP(
		"ovmf", "o", "", "OVMF used with this VM/TEE",
	)

	reportFile = cmd.Flags().StringP(
		"report", "r", "", "SEV-SNP ATTESTATION_REPORT binary LE format",
	)

	corimFile = cmd.Flags().StringP(
		"corim", "f", "", "Reference values for VM/TEE in CoRIM format",
	)

	return cmd
}

func composeRefVals(fs afero.Fs) error {
	refValCorim := corim.NewUnsignedCorim()
	if refValCorim.SetProfile(ProfileName) == nil {
		fmt.Println("Failed to set profile name to ", ProfileName)
	}
	refValCorim.SetID(uuid.New().String())

	for cpu := 1; cpu <= viper.GetInt("maxvcpus"); cpu++ {
		refValComid, err := ReportToComid(reportProto, cpu)
		if err != nil {
			return err
		}

		refValCorim.AddComid(*refValComid)
	}

	buf, err := refValCorim.ToCBOR()
	if err != nil {
		return err
	}

	if corimFile == nil || *corimFile == "" {
		s := fmt.Sprintf("/tmp/corim-%s.cbor", uuid.New().String())
		corimFile = &s
	}

	err = afero.WriteFile(fs, *corimFile, buf, 0644)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, ">>>>>>>> Generated %s >>>>>>>>\n", *corimFile)

	return nil
}
