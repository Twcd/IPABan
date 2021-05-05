using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPABan
{
    class IPDBApi
    {
        public class Error
        {
            public string detail { get; set; }
            public int status { get; set; }
        }


        #region JSONClass
        public class Report
        {
            public DateTime reportedAt { get; set; }
            public string comment { get; set; }
            public IList<int> categories { get; set; }
            public int reporterId { get; set; }
            public string reporterCountryCode { get; set; }
            public string reporterCountryName { get; set; }
        }

        public class Data
        {
            public string ipAddress { get; set; }
            public bool isPublic { get; set; }
            public int ipVersion { get; set; }
            public bool? isWhitelisted { get; set; }
            public int abuseConfidenceScore { get; set; }
            public string countryCode { get; set; }
            public string usageType { get; set; }
            public string isp { get; set; }
            public string domain { get; set; }
            public IList<object> hostnames { get; set; }
            public string countryName { get; set; }
            public int totalReports { get; set; }
            public int numDistinctUsers { get; set; }
            public DateTime? lastReportedAt { get; set; }
            public IList<Report> reports { get; set; }
        }

        public class CheckIPRequest
        {
            public List<Error> errors { get; set; }
            public Data data { get; set; }
        }

        public class ipStat
        {
            public int attemptCount;
            public long timeStamp;
            public string ip;
            public int banAmount = 0;
            public bool check = false;
        }

        public class Meta
        {
            public DateTime generatedAt { get; set; }
        }

        public class Datum
        {

            public string ipAddress { get; set; }
            public string countryCode { get; set; }
            public int abuseConfidenceScore { get; set; }
            public DateTime lastReportedAt { get; set; }
        }

        public class BlackListIPRequest
        {
            public Meta meta { get; set; }
            public IList<Datum> data { get; set; }
        }

        #endregion

        string GetBlackList()
        {
            var client = new RestClient("https://api.abuseipdb.com/api/v2/blacklist");
            var request = new RestRequest(Method.GET);
            request.AddHeader("Key", Config.apiKey);
            request.AddHeader("Accept", "application/json");
            request.AddParameter("confidenceMinimum", "90");

            IRestResponse response = client.Execute(request);

            dynamic parsedJson = JsonConvert.DeserializeObject(response.Content);

            foreach (var item in parsedJson)
            {
                Console.WriteLine(item);
            }

            return response.Content;
        }
        public static bool CheckIP(string _ip)
        {
            try
            {

                var client = new RestClient("https://api.abuseipdb.com/api/v2/check");
                var request = new RestRequest(Method.GET);
                request.AddHeader("Key", Config.apiKey);
                request.AddHeader("Accept", "application/json");
                request.AddParameter("ipAddress", _ip);
                request.AddParameter("maxAgeInDays", "90");
                request.AddParameter("verbose", "");

                IRestResponse response = client.Execute(request);
                var json = JsonConvert.DeserializeObject<CheckIPRequest>(response.Content);

                // Service1.WriteToFile(response.Content);

                if (json.errors.Count > 0)
                {
                    Service1.WriteError("Error from IPDB");
                    foreach (Error err in json.errors)
                    {
                        Service1.WriteError(err.detail);
                    }
                    return true;
                }
                else
                {
                    if (json.data.totalReports >= 3)
                    {
                        ReportIP(_ip, "Attempt windows login");
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
            }
            catch (Exception e)
            {
                Service1.WriteError("#3");
                Service1.WriteError(e.Message);
                return true;

            }
     
        }


        public static void ReportIP(string _reportip, string _reason)
        {
            try
            {

                Service1.WriteLog("Reporting user");
                var client = new RestClient("https://api.abuseipdb.com/api/v2/report");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Key", Config.apiKey);
                request.AddHeader("Accept", "application/json");
                request.AddParameter("ip", _reportip);
                request.AddParameter("categories", "18");
                request.AddParameter("comment", _reason + " (Reported with IPABan)");

                IRestResponse response = client.Execute(request);

                dynamic parsedJson = JsonConvert.DeserializeObject(response.Content);

                //foreach (var item in parsedJson)
                //{
                //    Service1.WriteToFile(item.ToString());
                //}               
            }
            catch(Exception e)
            {
                Service1.WriteError(e.Message);
            }
        }
    }
}
