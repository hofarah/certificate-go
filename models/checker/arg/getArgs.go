package arg

import "flag"

const File = "file"

func GetArg(key string) (bool, string) {
	argFile := File
	str := flag.String(argFile, "ca_root.cnf", "please set filepath of crt file")
	//todo some else args
	flag.Parse()
	ok := flag.Parsed()
	if key == File {
		return ok, *str
	}
	return false, ""
}
