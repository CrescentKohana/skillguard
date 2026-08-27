package scan

// isZeroWidth reports whether r is one of the SG001 zero-width/invisible characters.
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
		0xFEFF, 0x00AD, 0x180E, 0x3164, 0x115F, 0x1160, 0xFFA0:
		return true
	}
	return false
}

// isPictographic reports whether r is a pictographic character that may
// legitimately flank a ZWJ in an emoji sequence.
func isPictographic(r rune) bool {
	return (r >= 0x1F000 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF)
}

// isEmojiZWJException reports whether the ZWJ at runes[i] sits directly
// between two pictographic characters, forming a legitimate emoji sequence.
func isEmojiZWJException(runes []rune, i int) bool {
	prevIdx := i - 1
	if prevIdx < 0 {
		return false
	}
	if runes[prevIdx] == 0xFE0F {
		prevIdx--
	}
	if prevIdx < 0 || !isPictographic(runes[prevIdx]) {
		return false
	}
	nextIdx := i + 1
	if nextIdx >= len(runes) || !isPictographic(runes[nextIdx]) {
		return false
	}
	return true
}

// isBidi reports whether r is one of the SG002 bidirectional-control characters.
func isBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C:
		return true
	}
	return false
}

// isTagOrVariationSelector reports whether r is one of the SG003 Unicode Tag
// block or variation-selector-supplement characters.
func isTagOrVariationSelector(r rune) bool {
	return (r >= 0xE0000 && r <= 0xE007F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// isInvisible reports whether r is any character covered by SG001-SG003,
// used to render snippets and to strip noise before SG010 phrase matching.
func isInvisible(r rune) bool {
	return isZeroWidth(r) || isBidi(r) || isTagOrVariationSelector(r)
}
