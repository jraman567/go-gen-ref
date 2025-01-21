package sevsnp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/veraison/corim/comid"
	"github.com/veraison/swid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"strconv"
)

func ReportToComid(reportProto *sevsnp.Report, cpu int) (*comid.Comid, error) {
	var (
		err               error
		launchMeasurement []byte
		reportVersion     uint32
	)

	refValComid := comid.NewComid().
		SetLanguage("en-GB").
		SetTagIdentity(uuid.New(), 0)

	env := comid.Environment{}
	switch reportProto.GetSignerInfo() {
	case 0:
		env.Class = comid.NewClassOID(ClassIDByChip)
		if !isAllZeros(reportProto.GetChipId()) {
			env.Instance, err = comid.NewBytesInstance(reportProto.GetChipId())
			if err != nil {
				return nil, err
			}
		}
	case 1:
		env.Class = comid.NewClassOID(ClassIDByCsp)
		if viper.IsSet("cspId") {
			env.Instance, err = comid.NewBytesInstance([]byte(viper.GetString("cspId")))
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("invalid signer info: %d", reportProto.GetSignerInfo())
	}

	refVal := comid.ValueTriple{
		Environment:  env,
		Measurements: *comid.NewMeasurements(),
	}

	reportVersion = reportProto.GetVersion()

	/* MKey 0: VERSION */
	m0 := comid.MustNewUintMeasurement(uint(0))
	m0.SetVersion(strconv.Itoa(int(reportVersion)), swid.VersionSchemeDecimal)
	refVal.Measurements.Add(m0)

	/* MKey 1: GUEST_SVN */
	m1 := comid.MustNewUintMeasurement(uint(1))
	m1.SetMinSVN(uint64(reportProto.GetGuestSvn()))
	refVal.Measurements.Add(m1)

	/* MKey 2: POLICY */
	m2 := comid.MustNewUintMeasurement(uint(2))
	policy := make([]byte, 8)
	binary.BigEndian.PutUint64(policy, reportProto.GetPolicy())
	m2.SetRawValueBytes(policy, nil)
	refVal.Measurements.Add(m2)

	/* MKey 3: FAMILY_ID */
	m3 := comid.MustNewUintMeasurement(uint(3))
	familyId := make([]byte, 16)
	copy(familyId, reportProto.GetFamilyId())
	m3.SetRawValueBytes(familyId, nil)
	refVal.Measurements.Add(m3)

	/* MKey 4: IMAGE_ID */
	m4 := comid.MustNewUintMeasurement(uint(4))
	imageId := make([]byte, 16)
	copy(imageId, reportProto.GetImageId())
	m4.SetRawValueBytes(imageId, nil)
	refVal.Measurements.Add(m4)

	/* MKey 5: VMPL */
	m5 := comid.MustNewUintMeasurement(uint(5))
	vmpl := make([]byte, 4)
	binary.BigEndian.PutUint32(vmpl, reportProto.GetVmpl())
	m5.SetRawValueBytes(vmpl, nil)
	refVal.Measurements.Add(m5)

	/* MKey 6: CURRENT_TCB */
	m6 := comid.MustNewUintMeasurement(uint(6))
	m6.SetSVN(reportProto.GetCurrentTcb())
	refVal.Measurements.Add(m6)

	/* MKey 7: PLATFORM */
	m7 := comid.MustNewUintMeasurement(uint(7))
	platform := make([]byte, 8)
	binary.BigEndian.PutUint64(platform, reportProto.GetPlatformInfo())
	m7.SetRawValueBytes(platform, nil)
	refVal.Measurements.Add(m7)

	/* MKey 640: REPORT_DATA */
	if !isAllZeros(reportProto.GetReportData()) {
		m640 := comid.MustNewUintMeasurement(uint(640))
		reportData := make([]byte, 64)
		copy(reportData, reportProto.GetReportData())
		m640.SetRawValueBytes(reportData, nil)
		refVal.Measurements.Add(m640)
	}

	/* MKey 641: MEASUREMENT */
	m641 := comid.MustNewUintMeasurement(uint(641))
	if cpu > 0 {
		launchMeasurement, err = calcLaunchMeasurement(cpu)
	} else {
		launchMeasurement = reportProto.GetMeasurement()
	}

	if err != nil {
		return nil, fmt.Errorf("calc launch digest failed: %w", err)
	}
	m641.AddDigest(swid.Sha384, launchMeasurement)
	refVal.Measurements.Add(m641)

	/* MKey 642: HOST_DATA */
	if !isAllZeros(reportProto.GetHostData()) {
		m642 := comid.MustNewUintMeasurement(uint(642))
		hostData := make([]byte, 32)
		copy(hostData, reportProto.GetHostData())
		m642.SetRawValueBytes(hostData, nil)
		refVal.Measurements.Add(m642)
	}

	/* MKey 643: ID_KEY_DIGEST */
	if !isAllZeros(reportProto.GetIdKeyDigest()) {
		m643 := comid.MustNewUintMeasurement(uint(643))
		idKeyDigest := make([]byte, 48)
		copy(idKeyDigest, reportProto.GetIdKeyDigest())
		m643.SetRawValueBytes(idKeyDigest, nil)
		refVal.Measurements.Add(m643)
	}

	/* MKey 644: AUTHOR_KEY_DIGEST */
	if !isAllZeros(reportProto.GetAuthorKeyDigest()) {
		m644 := comid.MustNewUintMeasurement(uint(644))
		authorKeyDigest := make([]byte, 48)
		copy(authorKeyDigest, reportProto.GetAuthorKeyDigest())
		m644.SetRawValueBytes(authorKeyDigest, nil)
		refVal.Measurements.Add(m644)
	}

	/* MKey 645: REPORT_ID */
	if !isAllZeros(reportProto.GetReportId()) {
		m645 := comid.MustNewUintMeasurement(uint(645))
		reportId := make([]byte, 32)
		copy(reportId, reportProto.GetReportId())
		m645.SetRawValueBytes(reportId, nil)
		refVal.Measurements.Add(m645)
	}

	/* MKey 646: REPORT_ID_MA */
	if !isAllZeros(reportProto.GetReportIdMa()) {
		m646 := comid.MustNewUintMeasurement(uint(646))
		reportIdMa := make([]byte, 32)
		copy(reportIdMa, reportProto.GetReportIdMa())
		m646.SetRawValueBytes(reportIdMa, nil)
		refVal.Measurements.Add(m646)
	}

	/* MKey 647: REPORTED_TCB */
	m647 := comid.MustNewUintMeasurement(uint(647))
	m647.SetSVN(reportProto.GetReportedTcb())
	refVal.Measurements.Add(m647)

	if reportVersion >= abi.ReportVersion3 {
		f, m, s := abi.FmsFromCpuid1Eax(reportProto.GetCpuid1EaxFms())

		/* MKey 648: CPU_FAM_ID */
		m648 := comid.MustNewUintMeasurement(uint(648))
		m648.SetRawValueBytes([]byte{f}, nil)
		refVal.Measurements.Add(m648)

		/* MKey 649: CPU_MOD_ID */
		m649 := comid.MustNewUintMeasurement(uint(649))
		m649.SetRawValueBytes([]byte{m}, nil)
		refVal.Measurements.Add(m649)

		/* MKey 650: CPUID_STEP */
		m650 := comid.MustNewUintMeasurement(uint(650))
		m650.SetRawValueBytes([]byte{s}, nil)
		refVal.Measurements.Add(m650)
	}

	/* MKey 3328: CHIP_ID */
	if !isAllZeros(reportProto.GetChipId()) {
		m3328 := comid.MustNewUintMeasurement(uint(3328))
		chipId := make([]byte, 64)
		copy(chipId, reportProto.GetChipId())
		m3328.SetRawValueBytes(chipId, nil)
		refVal.Measurements.Add(m3328)
	}

	/* MKey 3329: COMMITTED_TCB */
	m3329 := comid.MustNewUintMeasurement(uint(3329))
	m3329.SetSVN(reportProto.GetCommittedTcb())
	refVal.Measurements.Add(m3329)

	/* MKey 3330: CURRENT_VERSION */
	m3330 := comid.MustNewUintMeasurement(uint(3330))
	currentVersion := fmt.Sprintf("%d.%d.%d",
		reportProto.GetCurrentMajor(),
		reportProto.GetCurrentMinor(),
		reportProto.GetCurrentBuild())
	m3330.SetVersion(currentVersion, swid.VersionSchemeSemVer)
	refVal.Measurements.Add(m3330)

	/* MKey 3936: COMMITTED_VERSION */
	m3936 := comid.MustNewUintMeasurement(uint(3936))
	committedVersion := fmt.Sprintf("%d.%d.%d",
		reportProto.GetCommittedMajor(),
		reportProto.GetCommittedMinor(),
		reportProto.GetCommittedBuild())
	m3936.SetVersion(committedVersion, swid.VersionSchemeSemVer)
	refVal.Measurements.Add(m3936)

	/* MKey 3968: LAUNCH_TCB */
	m3968 := comid.MustNewUintMeasurement(uint(3968))
	m3968.SetSVN(reportProto.GetLaunchTcb())
	refVal.Measurements.Add(m3968)

	refValComid.Triples.AddReferenceValue(refVal)

	err = refValComid.Valid()
	if err != nil {
		return nil, err
	}

	return refValComid, nil
}

func isAllZeros(buf []byte) bool {
	if bytes.Equal(buf, make([]byte, len(buf))) {
		return true
	}
	return false
}

func calcLaunchMeasurement(vcpuCount int) ([]byte, error) {
	ovmfObj, err := ovmf.New(*ovmfFile)
	if err != nil {
		return nil, err
	}

	ovmfHash, err := guest.OVMFHash(ovmfObj)
	if err != nil {
		return nil, err
	}

	launchDigest, err := guest.LaunchDigestFromOVMF(ovmfObj, 0x1 /* guest features */, vcpuCount, ovmfHash, vmmtypes.QEMU, viper.GetString("model"))
	if err != nil {
		return nil, err
	}

	return launchDigest, nil
}
