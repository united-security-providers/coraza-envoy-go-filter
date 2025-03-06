package main

import (
	"bytes"
	collect "coraza-waf/compare/collectPlugin"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type testingInfo struct {
	tp90    string
	tp99    string
	realQps float64
}

func main() {
	//testEnvoyGo(false, 50, 1000, 50, 600, "30s", time.Second*15)
	//testWasm(false, 50, 1000, 50, 600, "30s", time.Second*15)
	//testEnvoyGo(true, 50, 450, 50, 0, "2m", time.Minute)
	//testWasm(true, 50, 550, 50, 0, "2m", time.Minute)
	testWasmOne(true, 600, "2m", time.Minute)
	//testEnvoyGoOne(true, 500, "2m", time.Minute)
	//startEnvoyDockerWasm()
	//stopEnvoyDocker()
}

// This method is used to test envoy go with qps ranging from 50-1000
func testEnvoyGo(isBigBody bool, start, end, loop, retryLimit int, duration string, monitorTime time.Duration) {
	size := (end-start)/loop + 1
	envoyGoStressInfo := make([]*testingInfo, 0, size)
	hostInfo := make([]*collect.HostInfo, 0, size)
	for i := start; i <= end; i += loop {
		hostInfoChan := make(chan *collect.HostInfo)
		startEnvoyDockerGO()
		pid, err := getEnvoyPid()
		if err != nil {
			panic(err)
		}
		go startMonitor(pid, hostInfoChan, monitorTime)
		var test *testingInfo
		if isBigBody {
			test, err = startStressTestBigBody(strconv.Itoa(i), duration)
		} else {
			test, err = startStressTest(strconv.Itoa(i), duration)
		}
		if err != nil {
			panic(err)
		}
		info := <-hostInfoChan
		//Add a retry mechanism
		if i < retryLimit && (test.realQps < float64(i-10) || test.realQps > float64(i+10)) {
			i -= loop
		} else {
			envoyGoStressInfo = append(envoyGoStressInfo, test)
			hostInfo = append(hostInfo, info)
		}
		stopEnvoyDocker()
	}
	var open *os.File
	var err error
	if isBigBody {
		open, err = os.OpenFile("./envoyGoBigBodyTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	} else {
		open, err = os.OpenFile("./envoyGoTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	}
	if err != nil {
		panic("file path error")
	}
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	for i := 0; i < size; i++ {
		goStressInfo := envoyGoStressInfo[i]
		info := hostInfo[i]
		fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", goStressInfo.realQps, goStressInfo.tp90, goStressInfo.tp99, info.MemPercent, info.CpuPercent)
	}
}

// This method is used to test wasm with qps ranging from 50-1000
func testWasm(isBigBody bool, start, end, loop, retryLimit int, duration string, monitorTime time.Duration) {
	size := (end-start)/loop + 1
	wasmStressInfo := make([]*testingInfo, 0, size)
	hostInfo := make([]*collect.HostInfo, 0, size)
	for i := start; i <= end; i += loop {
		hostInfoChan := make(chan *collect.HostInfo)
		startEnvoyDockerWasm()
		pid, err := getEnvoyPid()
		if err != nil {
			panic(err)
		}
		go startMonitor(pid, hostInfoChan, monitorTime)
		var test *testingInfo
		if isBigBody {
			test, err = startStressTestBigBody(strconv.Itoa(i), duration)
		} else {
			test, err = startStressTest(strconv.Itoa(i), duration)
		}
		if err != nil {
			panic(err)
		}
		info := <-hostInfoChan
		//Add a retry mechanism
		if i < retryLimit && (test.realQps < float64(i-10) || test.realQps > float64(i+10)) {
			i -= loop
		} else {
			wasmStressInfo = append(wasmStressInfo, test)
			hostInfo = append(hostInfo, info)
		}
		stopEnvoyDocker()
	}
	var open *os.File
	var err error
	if isBigBody {
		open, err = os.OpenFile("./envoyWasmBigBodyTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	} else {
		open, err = os.OpenFile("./envoyWasmTestingData", os.O_CREATE|os.O_WRONLY, 0666)
	}
	if err != nil {
		panic("file path error")
	}
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	for i := 0; i < size; i++ {
		wasmInfo := wasmStressInfo[i]
		info := hostInfo[i]
		fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", wasmInfo.realQps, wasmInfo.tp90, wasmInfo.tp99, info.MemPercent, info.CpuPercent)
	}
}

// Test wasm by input qps
func testWasmOne(isBigBody bool, qps int, duration string, monitorTime time.Duration) (*testingInfo, *collect.HostInfo) {
	hostInfoChan := make(chan *collect.HostInfo)
	startEnvoyDockerWasm()
	pid, err := getEnvoyPid()
	if err != nil {
		panic(err)
	}
	var test *testingInfo
	go startMonitor(pid, hostInfoChan, monitorTime)
	if isBigBody {
		test, err = startStressTestBigBody(strconv.Itoa(qps), duration)
	} else {
		test, err = startStressTest(strconv.Itoa(qps), duration)
	}
	if err != nil {
		panic(err)
	}
	info := <-hostInfoChan
	stopEnvoyDocker()
	open, err := os.OpenFile("./WasmOne", os.O_CREATE|os.O_WRONLY, 0666)
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", test.realQps, test.tp90, test.tp99, info.MemPercent, info.CpuPercent)
	return test, info
}

// Test wasm by input qps
func testEnvoyGoOne(isBigBody bool, qps int, duration string, monitorTime time.Duration) (*testingInfo, *collect.HostInfo) {
	hostInfoChan := make(chan *collect.HostInfo)
	startEnvoyDockerGO()
	pid, err := getEnvoyPid()
	if err != nil {
		panic(err)
	}
	var test *testingInfo
	go startMonitor(pid, hostInfoChan, monitorTime)
	if isBigBody {
		test, err = startStressTestBigBody(strconv.Itoa(qps), duration)
	} else {
		test, err = startStressTest(strconv.Itoa(qps), duration)
	}
	if err != nil {
		panic(err)
	}
	info := <-hostInfoChan
	stopEnvoyDocker()
	open, err := os.OpenFile("./EnvoyGoOne", os.O_CREATE|os.O_WRONLY, 0666)
	fmt.Fprintln(open, "realQps    tp90    tp99    mem    cpu")
	fmt.Fprintf(open, "%.2f    %s    %s    %.2f    %.2f\n", test.realQps, test.tp90, test.tp99, info.MemPercent, info.CpuPercent)
	return test, info
}

func startEnvoyDockerGO() {
	command := exec.Command("docker", "run", "--rm", "-d", "-e", "GODEBUG=cgocheck=0", "-v", "./envoy_go/envoy.yaml:/etc/envoy/envoy.yaml", "-v", "./envoy_go/coraza-waf.so:/etc/envoy/coraza-waf.so", "-p", "10000:10000", "envoyproxy/envoy:contrib-dev", "envoy", "-c", "/etc/envoy/envoy.yaml")
	_, err := command.CombinedOutput()
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 5)
}

func startEnvoyDockerWasm() {
	command := exec.Command("docker", "run", "--rm", "-d", "-v", "./wasm/envoy-config.yaml:/etc/envoy/envoy.yaml", "-v", "./wasm/main.wasm:/etc/envoy/main.wasm", "-p", "10000:10000", "envoyproxy/envoy:contrib-dev", "envoy", "-c", "/etc/envoy/envoy.yaml")
	_, err := command.CombinedOutput()
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 5)
}

func stopEnvoyDocker() {
	time.Sleep(time.Second * 2)
	command := exec.Command("docker", "ps")
	output, err := getOutput(command)
	if err != nil {
		panic(err)
	}
	split := bytes.Split(output, []byte("\n"))
	var containerId string
	for _, i2 := range split {
		if bytes.Contains(i2, []byte("envoyproxy/envoy")) {
			containnerSplit := bytes.Split(i2, []byte(" "))
			containerId = string(containnerSplit[0])
			break
		}
	}
	stopCommand := exec.Command("docker", "stop", containerId)
	_, err = stopCommand.CombinedOutput()
	if err != nil {
		panic(err)
	}
}

func getEnvoyPid() (int, error) {
	command := exec.Command("ps", "-ef")
	commandVGrep := exec.Command("grep", "-v", "grep")
	commandVDocker := exec.Command("grep", "-v", "docker")
	commandPGrep := exec.Command("pgrep", "envoy")
	var err error
	commandVGrep.Stdin, err = command.StdoutPipe()
	if err != nil {
		return 0, err
	}
	commandVDocker.Stdin, err = commandVGrep.StdoutPipe()
	if err != nil {
		return 0, err
	}
	commandPGrep.Stdin, err = commandVDocker.StdoutPipe()
	if err != nil {
		return 0, err
	}
	output, err := getOutput(commandPGrep)
	if err != nil {
		panic(err)
	}
	atoi, err := strconv.Atoi(string(bytes.TrimSpace(output)))
	if err != nil {
		return 0, err
	}
	return atoi, nil
}

func startMonitor(pid int, infoChan chan<- *collect.HostInfo, duration time.Duration) error {
	newMonitor, err := collect.NewMonitor(int32(pid), duration, "", false)
	if err != nil {
		return err
	}
	info := newMonitor.CollectInfo(1)
	infoChan <- info[0]
	return nil
}

func startStressTest(qps string, duration string) (*testingInfo, error) {
	command := exec.Command("./wrk/wrk", "-t", "4", "-c", "400", "-d", duration, "-R", qps, "--latency", "http://localhost:10000/ping")
	output, err := getOutput(command)
	if err != nil {
		return nil, err
	}
	return parseTestInfo(output)
}

func startStressTestBigBody(qps string, duration string) (*testingInfo, error) {
	command := exec.Command("./wrk/wrk", "-t", "4", "-c", "400", "-d", duration, "-s", "./lua/bigBody.lua", "-R", qps, "--latency", "http://localhost:10000")
	output, err := getOutput(command)
	if err != nil {
		return nil, err
	}
	return parseTestInfo(output)
}

func parseTestInfo(output []byte) (*testingInfo, error) {
	info := &testingInfo{}
	split := bytes.Split(output, []byte("\n"))
	for _, i2 := range split {
		if bytes.Contains(i2, []byte("90.000%")) {
			splitTp90 := bytes.Split(i2, []byte(" "))
			for i := len(splitTp90) - 1; i >= 0; i-- {
				tp90 := splitTp90[i]
				if len(tp90) != 0 {
					info.tp90 = string(bytes.TrimSpace(tp90))
					break
				}
			}
		}
		if bytes.Contains(i2, []byte("99.000%")) {
			splitTp99 := bytes.Split(i2, []byte(" "))
			for i := len(splitTp99) - 1; i >= 0; i-- {
				tp99 := splitTp99[i]
				if len(tp99) != 0 {
					info.tp99 = string(bytes.TrimSpace(tp99))
					break
				}
			}
		}
		var err error
		if bytes.Contains(i2, []byte("Requests/sec:")) {
			splitQps := bytes.Split(i2, []byte(" "))
			for i := len(splitQps) - 1; i >= 0; i-- {
				qps := splitQps[i]
				if len(qps) != 0 {
					info.realQps, err = strconv.ParseFloat(string(qps), 64)
					if err != nil {
						return nil, err
					}
					break
				}
			}
		}
	}
	return info, nil
}

func getOutput(command *exec.Cmd) ([]byte, error) {
	var stdout io.ReadCloser
	var err error
	if stdout, err = command.StdoutPipe(); err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err = command.Start(); err != nil {
		return nil, err
	}
	var all []byte
	if all, err = ioutil.ReadAll(stdout); err != nil {
		return nil, err
	}
	return all, nil
}
