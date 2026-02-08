package extractor

func GetMagicHeader(data []byte) string {
	return ExtractMagicHeader(data)
}

func GetUintString(magic string) string {
	if len(magic) == 2 {
		return "uint8(0) == 0x" + magic
	}
	if len(magic) == 4 {
		return "uint16(0) == 0x" + magic[2:4] + magic[0:2]
	}
	return ""
}

func GetFileRange(size int64, multiplier int) string {
	if size <= 0 {
		return ""
	}
	if multiplier <= 0 {
		multiplier = 3
	}

	maxSize := size * int64(multiplier)
	if maxSize < 1024 {
		maxSize = 1024
	}

	maxSizeKB := maxSize / 1024

	switch {
	case maxSizeKB < 100:
		maxSizeKB = ((maxSizeKB + 9) / 10) * 10
	case maxSizeKB < 1000:
		maxSizeKB = ((maxSizeKB + 99) / 100) * 100
	default:
		maxSizeKB = ((maxSizeKB + 999) / 1000) * 1000
	}

	return formatFilesizeCondition(maxSizeKB)
}

func formatFilesizeCondition(sizeKB int64) string {
	if sizeKB >= 1024 && sizeKB%1024 == 0 {
		return "filesize < " + itoa(sizeKB/1024) + "MB"
	}
	return "filesize < " + itoa(sizeKB) + "KB"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}

	var buf [20]byte
	i := len(buf)
	negative := n < 0
	if negative {
		n = -n
	}

	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if negative {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
