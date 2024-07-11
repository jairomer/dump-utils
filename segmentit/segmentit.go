package main

import (
    //"fmt"
    "os"
    "io"
    "bufio"
    "log"
    "regexp"

    "github.com/schollz/progressbar/v3"
)


type PatternMatcher struct {
    output_directory string
    patterns map[string]*regexp.Regexp
    files map[string]*os.File
    writers map[string]*bufio.Writer
}

func NewPatternMatcher(output_dir string) (*PatternMatcher) {
    matcher := PatternMatcher {}

    matcher.patterns = make(map[string]*regexp.Regexp)
    matcher.files = make(map[string]*os.File)
    matcher.writers = make(map[string]*bufio.Writer)
    matcher.output_directory = output_dir
    
    matcher.patterns["md5"]      = regexp.MustCompile(`\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}`) 
    matcher.patterns["sha256"]   = regexp.MustCompile(`\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}`) 
    matcher.patterns["sha512"]   = regexp.MustCompile(`\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}`)
    matcher.patterns["blowfish"] = regexp.MustCompile(`\$2[ayb]\$[./0-9A-Za-z]{2}\$[./0-9A-Za-z]{53}`)
    matcher.patterns["des"]      = regexp.MustCompile(`[./0-9A-Za-z]{13}`)
    matcher.patterns["bigcrypt"] = regexp.MustCompile(`[./0-9A-Za-z]{13,}`)
    matcher.patterns["nthash"]   = regexp.MustCompile(`[0-9A-Fa-f]{32}`)
    matcher.patterns["crypt"]    = regexp.MustCompile(`_[./0-9A-Za-z]{19}`)
    matcher.patterns["lanman"]   = regexp.MustCompile(`[0-9A-Fa-f]{32}`)
    matcher.patterns["email"]    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
    return &matcher
}

func (pm *PatternMatcher) CloseAll() {
    for _, file := range pm.files {
        file.Close()
    }
}

func (pm *PatternMatcher) pushToFile(line string, tag string) error {
    writer, isInitialized := pm.writers[tag]
    err := error(nil)
    if !isInitialized {
        filename := pm.output_directory+"/"+tag+".txt"
        pm.files[tag], err = os.Create(filename)
        if err != nil {
            return err
        }
        writer = bufio.NewWriter(pm.files[tag])
        pm.writers[tag] = writer
    }
    _, err = writer.WriteString(line)
    if err != nil {
        log.Fatal(err)
    }
    return err
}

func (pm *PatternMatcher) saveAsset(line string) error {
    // Unidentified asset
    for _, matcher := range pm.patterns {
        if matcher.MatchString(line) {
            //fmt.Printf("%s': %s'", hash, line)
            //err := pm.pushToFile(line, tag)
            //if err != nil {
            //    log.Fatal(err)
            //}
            return nil
        }
    }
    err := pm.pushToFile(line, "else")
    if err != nil {
        log.Fatal(err)
    }
    return nil
}

func main() {
    if len(os.Args) < 2 {
        log.Fatal("Usage: segmentit <file>")
    }
    filename := os.Args[1]

    f, err := os.Open(filename)
    defer f.Close()
    if err != nil {
        log.Fatal(err)
    }

    fileInfo, err := f.Stat()
    if err != nil {
        log.Fatal(err)
    }
   
    directory := ""
    for i:=len(filename)-1; i>=0; i-- {
        if filename[i] == '/' {
            directory = string(filename[:i+1])
            break;
        }
    }
    
    pm := NewPatternMatcher(directory)
    defer pm.CloseAll()

    reader := bufio.NewReader(f)

    const PROGRESS_UNIT = 1024*1024 // MB
    total :=  fileInfo.Size()/ PROGRESS_UNIT
    byteCounter := 0
    bar := progressbar.Default(total)

    for {
        line, err := reader.ReadString('\n');
        if err != nil {
            if err == io.EOF {
                break;
            }
            log.Fatal(err)
        }

        err = pm.saveAsset(line)
        if err != nil {
            log.Fatal(err)
        }

        byteCounter = byteCounter+len(line)
        if byteCounter > PROGRESS_UNIT {
            bar.Add(1)
            byteCounter = 0
        }
    }

}
