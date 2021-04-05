using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Xml;
using System.ServiceProcess;
using System.Collections.Generic;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using System.Threading;

namespace IPABan
{
    public partial class Service1 : ServiceBase
    {
        class ipStat
        {
            public int attemptCount;
            public long timeStamp;
            public string ip;
        }
        List<ipStat> ipAttempt = new List<ipStat>();
        List<IAddress> bannedIP = new List<IAddress>();

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            WriteToFile("Service is started. " + DateTime.Now);
            FindRule();
            RegisterListener();
            Thread trd = new Thread(new ThreadStart(this.FirewallUpdater));
            trd.IsBackground = true;
            trd.Start();

        }


        void FirewallUpdater()
        {
            while(true)
            {
                Thread.Sleep(6000);
                foreach(ipStat ip in ipAttempt)
                {
                    if(ip.timeStamp >= DateTime.Now.ToFileTime() + 36000)
                    {
                        bannedIP.Remove(SingleIP.Parse(ip.ip));
                        FirewallUpdate();
                    }
                }
            }
        }

        private void OnEntryWritten(object source, EntryWrittenEventArgs e)
        {
            string watchLog = "Security";
            string logName = watchLog;
            int e1 = 0;
            EventLog log = new EventLog(logName);

            e1 = log.Entries.Count - 1; // last entry

            if (log.Entries[e1].InstanceId == 4625)
            {



                string query = @"*[System[(EventID = 4625)]]";
                EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
                try
                {
                    eventsQuery.ReverseDirection = true;
                    EventLogReader logReader = new EventLogReader(eventsQuery);

                    //WriteToFile("Description : " + logReader.ReadEvent().ToXml());
                    XmlReader reader = XmlReader.Create(new StringReader(logReader.ReadEvent().ToXml()));
                    while (reader.Read())
                    {
                        if (reader.IsStartElement())
                        {
                            //WriteToFile(reader.Name + ":" + reader.Value);
                            switch (reader.Name.ToString())
                            {
                                case "Data":
                                    if (reader.GetAttribute(0) == "TargetUserName")
                                    {
                                        WriteToFile("Connection attemps with username : " + reader.ReadElementContentAsString());

                                    }
                                    if (reader.GetAttribute(0) == "IpAddress")
                                    {
                                        string ipAddress = reader.ReadElementContentAsString();
                                        int idxIP = FindIP(ipAddress);
                                        if (idxIP == -1)
                                        {
                                            ipStat newStat = new ipStat();
                                            newStat.timeStamp = DateTime.Now.ToFileTime();
                                            newStat.ip = ipAddress;
                                            newStat.attemptCount = 1;
                                            ipAttempt.Add(newStat);
                                        }
                                        else
                                        {

                                            ipAttempt[idxIP].attemptCount++;
                                            if (ipAttempt[idxIP].attemptCount >= 5)
                                            {
                                                WriteToFile("BAN THIS IP");

                                                IRule rule1 = FindRule();

                                                bannedIP.Add(SingleIP.Parse(ipAddress.ToString()));
                                                if (rule1 == null)
                                                {
                                                    WriteToFile("Create rule");

                                                    var rule = FirewallManager.Instance.CreateApplicationRule(
                                                         FirewallManager.Instance.GetProfile().Type,
                                                         @"IPABan",
                                                         FirewallAction.Block,
                                                         null
                                                    );
                                                    rule.Direction = FirewallDirection.Inbound;
                                                    rule.LocalPorts = new ushort[] { 3389 };
                                                    rule.Action = FirewallAction.Block;
                                                    rule.Protocol = FirewallProtocol.Any;
                                                    rule.Scope = FirewallScope.All;
                                                    rule.Profiles = FirewallProfiles.Public | FirewallProfiles.Private;

                                                    rule.RemoteAddresses = bannedIP.ToArray();
                                                    FirewallManager.Instance.Rules.Add(rule);
                                                    WriteToFile("Rule created");
                                                }
                                                else
                                                {
                                                    FirewallUpdate();
                                                }
                                            }
                                        }
                                        WriteToFile(ipAttempt[0].attemptCount.ToString());

                                    }
                                    break;
                            }
                        }
                    }
                }
                catch (EventLogNotFoundException)
                {
                    Console.WriteLine("Error while reading the event logs");
                    return;
                }
            }
        }


        void FirewallUpdate()
        {            
            FirewallManager.Instance.Rules.Remove(FindRule());
            var rule = FirewallManager.Instance.CreateApplicationRule(
                  FirewallManager.Instance.GetProfile().Type,
                  @"IPABan",
                  FirewallAction.Block,
                  null
             );
            rule.Direction = FirewallDirection.Inbound;
            rule.LocalPorts = new ushort[] { 3389 };
            rule.Action = FirewallAction.Block;
            rule.Protocol = FirewallProtocol.Any;
            rule.Scope = FirewallScope.All;
            rule.Profiles = FirewallProfiles.Public | FirewallProfiles.Private;


            rule.RemoteAddresses = bannedIP.ToArray();
            FirewallManager.Instance.Rules.Add(rule);
        }

        IRule FindRule()
        {
            foreach (IRule rule in FirewallManager.Instance.Rules)
            {
                if (rule.Name == "IPABan")
                {
                    return rule;
                }
            }
            return null;
        }

        int FindIP(string _ip)
        {
            foreach (ipStat ip in ipAttempt)
            {
                if (ip.ip == _ip)
                {
                    return ipAttempt.IndexOf(ip);
                }
            }
            return -1;
        }

        public static void WriteToFile(string text)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            string ext = ".txt";
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            string filePath = path + "\\ServiceLog" + DateTime.Now.Date.ToShortDateString().Replace("/", "_") + ext;


            if (!File.Exists(filePath))
            {
                using (StreamWriter sw = File.CreateText(filePath))
                {
                    sw.WriteLine(text);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filePath))
                {
                    sw.WriteLine(text);
                }
            }

        }


        void RegisterListener()
        {
            string watchLog = "Security";
            EventLog myLog = new EventLog(watchLog);
            myLog.EntryWritten += new EntryWrittenEventHandler(OnEntryWritten);
            myLog.EnableRaisingEvents = true;
        }

        protected override void OnStop()
        {
        }
    }
}
