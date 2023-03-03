package collector

import (
	"context"
	"regexp"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
	//promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	//"github.com/prometheus/client_golang/prometheus/promauto"
	//"github.com/prometheus/client_golang/prometheus/promhttp"
	//"github.com/prometheus/common/promlog"
	//"github.com/prometheus/common/version"

	corev1 "k8s.io/api/core/v1"
)

// Regex constants
const (
	loginSuccessHtpasswdRegex = `Login with provider "(.*?)" succeeded for "(.*?)"`
	loginFailHtpasswdRegex    = `Login with provider "(.*?)" failed for "(.*?)"`
	loginSuccessOAuthRegex    = `.*\] (.*?) authentication succeeded:.*\{Name:"(.*?)",.*`
	loginFailOAuthRegex       = `.*\] (.*?) authentication failed:.*\{Name:"(.*?)",.*`
)

// Regex constants array. REMEMBER to update this list if you include a new
// regex for parsing logs
var listOfRegex = []string{
	loginSuccessHtpasswdRegex,
	loginSuccessOAuthRegex,
	loginFailHtpasswdRegex,
	loginFailOAuthRegex,
}

// Collector constants
const (
	loginAttempts           = "login_attempts"
	authenticationNamespace = "openshift-authentication"
)

//Wait Group for log parsing threads managing
var wg sync.WaitGroup

// Metrics Descriptors
var (
	loginsSucceededDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, loginAttempts, "successful"),
		"The ammount of succeeded login actions",
		[]string{"auth_provider", "user"},
		nil,
	)
	loginsFailedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, loginAttempts, "failed"),
		"The ammount of failed login actions",
		[]string{"auth_provider", "user"},
		nil,
	)
)

// LoginAttempts used to collect and count how many login attempts were performed by each user and each provider
type LoginAttempts struct {
	Attempts map[string]map[string]int
}

func (l *LoginAttempts) addAttempt(user string, provider string) {
	// Init user 1st level map
	if l.Attempts == nil {
		l.Attempts = map[string]map[string]int{}
	}

	// Init provider 2nd level map
	if _, ok := l.Attempts[user]; !ok {
		l.Attempts[user] = map[string]int{}
	}

	// Add or increment count for each provider
	if _, ok := l.Attempts[user][provider]; !ok {
		l.Attempts[user][provider] = 1
	} else {
		l.Attempts[user][provider]++
	}
}

func (l *LoginAttempts) getUserList() []string {
	var userList []string
	for user := range l.Attempts {
		userList = append(userList, user)
	}
	return userList
}

func (l *LoginAttempts) getProviderList() []string {
	var providerList []string
	for user := range l.Attempts {
		for provider := range l.Attempts[user] {
			providerList = append(providerList, provider)
		}
	}
	return providerList
}

func (l *LoginAttempts) countLoginAttempts(user string, provider string) int {
	if _, ok := l.Attempts[user]; !ok {
		if count, ok := l.Attempts[user][provider]; !ok {
			return count
		}
	}
	return 0
}

// ScrapeLogginAttempts collects login attempts history
type ScrapeLogginAttempts struct{}

// Name of the Scraper
func (ScrapeLogginAttempts) Name() string {
	return "login_attempts"
}

// Help describes the role of the Scraper.
func (ScrapeLogginAttempts) Help() string {
	return "Collect from Openshift Authentication Operator pod's logs"
}

// Version of MySQL from which scraper is available.
func (ScrapeLogginAttempts) Version() float64 {
	return 1.0
}

// Scrape collects data from authentication pods and sends it over channel as prometheus metric.
func (ScrapeLogginAttempts) Scrape(ch chan<- prometheus.Metric, logger log.Logger) error {
	var err error

	// Get K8s config
	clientConfig, err := getK8sConfig(logger)
	if err != nil {
		return err
	}

	// Get K8s client
	clientSet, err := getK8sClient(clientConfig, logger)
	if err != nil {
		return err
	}

	// Get list of authentication Pods names
	pods, err := getAuthPods(context.TODO(), clientSet, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to obtain the list of openshift-authentication pods", "err", err)
		return err
	}

	// Channel size is equals to # of auth pods
	numPods := len(pods.Items)
	successfulLoginChannel := make(chan *LoginAttempts, len(listOfRegex)*numPods)
	failedLoginChannel := make(chan *LoginAttempts, len(listOfRegex)*numPods)

	// TODO try to improve performance
	for _, pod := range pods.Items {
		wg.Add(1)
		go func(pod corev1.Pod) {
			defer wg.Done()

			// waitGroup and function used to paralelize parsing tasks
			//getterFunc := func(ch *chan *LoginAttempts, regex string, logs *[]string) {
			//	*ch <- getLoginActions(regex, logs)
			//}

			// Get logs
			logs, _ := getPodLogs(context.TODO(), clientSet, pod, logger)

			//getterFunc(&successfulLoginChannel, loginSuccessHtpasswdRegex, &logs)
			//getterFunc(&successfulLoginChannel, loginFailHtpasswdRegex, &logs)
			//getterFunc(&successfulLoginChannel, loginSuccessOAuthRegex, &logs)
			//getterFunc(&successfulLoginChannel, loginFailOAuthRegex, &logs)
			successfulLoginChannel <- getLoginActions(loginSuccessHtpasswdRegex, logs)
			failedLoginChannel <- getLoginActions(loginFailHtpasswdRegex, logs)
			successfulLoginChannel <- getLoginActions(loginSuccessOAuthRegex, logs)
			failedLoginChannel <- getLoginActions(loginFailOAuthRegex, logs)
		}(pod)
		level.Info(logger).Log("msg", "Scraping logs from auth pod", "pod", pod.Name)
	}
	wg.Wait()

	level.Info(logger).Log("msg", "Login Attempts collected. Pushing metrics")
	close(successfulLoginChannel)
	close(failedLoginChannel)
	pushLoginAttemptsIntoMetricsChannel(ch, successfulLoginChannel, loginsSucceededDesc, logger)
	pushLoginAttemptsIntoMetricsChannel(ch, failedLoginChannel, loginsFailedDesc, logger)

	return nil
}

func getLoginActions(regex string, logLines []string) *LoginAttempts {
	return loginMatchesToLoginAttempts(
		getLoginMatchesByRegex(regex, &logLines),
	)
}

func loginMatchesToLoginAttempts(results [][]string) *LoginAttempts {
	var attempts LoginAttempts
	for i := range results {
		// Fixed array position based Regex '()' User: 0; Provider: 1;
		attempts.addAttempt(results[i][0], results[i][1])
	}
	return &attempts
}

func pushLoginAttemptsIntoMetricsChannel(metricsCh chan<- prometheus.Metric, attemptsCh chan *LoginAttempts, metricDesc *prometheus.Desc, logger log.Logger) {
	var mergedAttempts LoginAttempts

	// Collect results from every thread opened to proccess logs
	for attempts := range attemptsCh {
		users := attempts.getUserList()
		providers := attempts.getProviderList()
		for i := range users {
			for j := range providers {
				for n := 0; n < attempts.Attempts[users[i]][providers[j]]; n++ {
					mergedAttempts.addAttempt(users[i], providers[j])
				}
			}
		}
	}

	// Sending Metrics
	for i := range mergedAttempts.Attempts {
		for j := range mergedAttempts.Attempts[i] {
			metricsCh <- prometheus.MustNewConstMetric(
				metricDesc,
				prometheus.CounterValue,
				float64(mergedAttempts.Attempts[i][j]),
				i,
				j,
			)
		}
	}

}

func getLoginMatchesByRegex(regex string, logLines *[]string) [][]string {
	re := regexp.MustCompile(regex)
	var loginAttempts [][]string
	for _, line := range *logLines {
		matches := re.FindAllStringSubmatch(line, -1)
		for i := range matches {
			// Fixed array position based Regex '()'
			// Starts at 1 instead 0 to avoid the first result which contains the entire matched string
			user := matches[i][1]
			provider := matches[i][2]
			loginAttempts = append(loginAttempts, []string{user, provider})
		}
	}

	return loginAttempts
}

func countLogsByRegex(regex string, logLines *[]string) int {
	count := 0
	// TODO get and return user
	re := regexp.MustCompile(regex)
	for _, line := range *logLines {
		matches := re.FindAllString(line, -1)
		count += len(matches)
	}
	return count
}

var _ Scraper = ScrapeLogginAttempts{}
