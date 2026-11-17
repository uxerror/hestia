//go:build !desktop

package selfinstall

func embeddedBinary() ([]byte, bool) { return nil, false }

const desktopBuild = false
