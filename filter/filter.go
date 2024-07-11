package main

import (
    "flag"
    "os"
    "io"
    "bufio"
    "log"
    "regexp"
    "fmt"
)

type FilterOptions struct {
    md5      bool
    sha256   bool
    sha512   bool
    blowfish bool
    des      bool
    bigcrypt bool
    nthash   bool
    crypt    bool
    lanman   bool
    email    bool
}

type PatternFilter struct {
    patterns map[string]*regexp.Regexp
}

func NewPatternFilter(options *FilterOptions) (*PatternFilter) {
    matcher := PatternFilter {}
    matcher.patterns = make(map[string]*regexp.Regexp)
    
    if options.md5 {
        matcher.patterns["md5"] = regexp.MustCompile(`\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}`) 
    }

    if options.sha256 {
        matcher.patterns["sha256"] = regexp.MustCompile(`\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}`) 
    }

    if options.sha512 {
        matcher.patterns["sha512"] = regexp.MustCompile(`\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}`)
    }

    if options.blowfish {
        matcher.patterns["blowfish"] = regexp.MustCompile(`\$2[ayb]\$[./0-9A-Za-z]{2}\$[./0-9A-Za-z]{53}`)
    }

    if options.des {
        matcher.patterns["des"] = regexp.MustCompile(`[./0-9A-Za-z]{13}`)
    }

    if options.bigcrypt {
        matcher.patterns["bigcrypt"] = regexp.MustCompile(`[./0-9A-Za-z]{13,}`)
    }

    if options.nthash {
        matcher.patterns["nthash"]   = regexp.MustCompile(`[0-9A-Fa-f]{32}`)
    }

    if options.crypt {
        matcher.patterns["crypt"]    = regexp.MustCompile(`_[./0-9A-Za-z]{19}`)
    }

    if options.lanman {
        matcher.patterns["lanman"]   = regexp.MustCompile(`[0-9A-Fa-f]{32}`)
    }

    if options.email {
        matcher.patterns["email"]    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
    }

    return &matcher
}

func (pm *PatternFilter) Match(line string) bool {
    for _, matcher := range pm.patterns {
        if matcher.MatchString(line) {
            return true
        }
    }
    return false
}

func main() {
    var flagmd5  = flag.Bool("md5", false, "Filter out md5 hashes")
    var flagsha256 = flag.Bool("sha256", false, "Filter out sha256 hashes")
    var flagsha512 = flag.Bool("sha512", false, "Filter out sha512 hashes")
    var flagblowfish = flag.Bool("blowfish", false, "Filter out blowfish hashes")
    var flagdes = flag.Bool("des", false, "Filter out des hashes")
    var flagbigcrypt = flag.Bool("bigcrypt", false, "Filter out bigcrypt hashes")
    var flagnthash = flag.Bool("nt", false, "Filter out Widows NT hashes")
    var flagcrypt = flag.Bool("crypt", false, "Filter out C crypt hashes")
    var flaglanman = flag.Bool("lanman", false, "Filter out lanman hashes")
    var flagemail = flag.Bool("email", false, "Filter out everything that looks like an email")

    var flagtargetfile = flag.String("target", "", "Select the file to filter")
    var flagstdin = flag.Bool("stdin", false, "Receive the file through the standard input")
    
    //var flagoutputfile = flag.String("output", "", "Set the output file")
    //var flagstdout = flag.Bool("stdout", true, "Receive the file through the standard input")
    
    flag.Parse()
    
    filteropt := FilterOptions {
        md5      : *flagmd5,
        sha256   : *flagsha256,
        sha512   : *flagsha512,
        blowfish : *flagblowfish,
        des      : *flagdes, 
        bigcrypt : *flagbigcrypt,
        nthash   : *flagnthash, 
        crypt    : *flagcrypt,
        lanman   : *flaglanman,
        email    : *flagemail,
    }
    filter := NewPatternFilter(&filteropt)

    // Setup reader
    var reader *bufio.Reader
    if (*flagtargetfile) == "" && !(*flagstdin) {
        log.Fatal("Use -target=<file> to select the file or --stdin to receive from standard input")
    } else if (*flagtargetfile) != "" && (*flagstdin) {
        log.Fatal("Cannot use -target=<file> and --stdin at the same time.")
    } else if !(*flagstdin) && (*flagtargetfile) != "" {
        f, err := os.Open(*flagtargetfile)
        defer f.Close()
        if err != nil {
            log.Fatal(err)
        }
        reader = bufio.NewReader(f)
    } else if (*flagstdin) {
        reader = bufio.NewReader(os.Stdin) 
    }

    // Setup writer(s)
//    var outwriter  *bufio.Writer
//    var filewriter *bufio.Writer
//    if !(*flagstdout) && (*flagoutputfile) == "" {
//        outwriter = bufio.NewWriter(os.Stdout)
//    }
//    if (*flagoutputfile) != "" {
//        outputfile, err := os.Create(*flagoutputfile)
//        if err != nil {
//            log.Fatal(err)
//        }
//        outwriter = bufio.NewWriter(outputfile)
//    }

    for {
        line, err := reader.ReadString('\n');
        if err != nil {
            if err == io.EOF {
                break;
            }
            log.Fatal(err)
        }
        if !filter.Match(line) {
            fmt.Printf("%s", line)
        }
//            if outwriter != nil {
//                _, err := outwriter.WriteString(line)
//                if err != nil {
//                    log.Fatal(err)
//                }
//                outwriter.Flush()
//            }
//            if filewriter != nil {
//                _, err := filewriter.WriteString(line)
//                if err != nil {
//                    log.Fatal(err)
//                }
//            }
//        }
    }
}
