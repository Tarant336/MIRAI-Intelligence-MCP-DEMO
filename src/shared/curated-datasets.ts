/**
 * Curated reference datasets (§12 of the platform specification).
 *
 * A small, hand-reviewed knowledge module of widely documented public facts
 * about the Mirai/IoT botnet ecosystem: notable Mirai lineage families,
 * frequently exploited IoT/embedded CVEs and public research datasets.
 *
 * Every entry is either a directly verifiable public fact (a vendor advisory,
 * an NVD record, a published dataset) or is explicitly marked with a lower
 * confidence level. No CVE identifiers, product versions or vendor claims are
 * invented. Sources are always attached so downstream tools can re-verify.
 *
 * Defensive posture only: this module documents malware lineages and
 * vulnerabilities for detection, attribution and defence.
 */

import { z } from 'zod';

export interface MiraiVariantRef {
  name: string;
  aliases: string[];
  firstSeen: string;
  summary: string;
  notableTraits: string[];
  sources: Array<{ title: string; url: string }>;
  confidence: 'confirmed' | 'observed' | 'inferred';
}

export interface IotCveRef {
  cve: string;
  vendor: string;
  product: string;
  classText: string;
  description: string;
  sources: Array<{ title: string; url: string }>;
  confidence: 'confirmed' | 'observed' | 'inferred';
}

export interface IotMalwareDatasetRef {
  name: string;
  url: string;
  licence: string;
  description: string;
  format: string;
  malwareFamilies: string[];
  archScope: string[];
  knownLimitations: string[];
  potentialBias: string[];
  reproducibility: string;
}

/* ------------------------------------------------------------------------- */
/* Schema validation (§P2.2)                                                 */
/* ------------------------------------------------------------------------- */

/** Confidence levels a curated reference is allowed to carry. */
const confidenceLevelSchema = z.enum(['confirmed', 'observed', 'inferred']);

const referenceSourceSchema = z.object({
  title: z.string().min(1),
  url: z.string().url(),
});

export const miraiVariantRefSchema = z.object({
  name: z.string().min(1),
  aliases: z.array(z.string()),
  firstSeen: z.string().min(1),
  summary: z.string().min(1),
  notableTraits: z.array(z.string().min(1)).min(1),
  sources: z.array(referenceSourceSchema).min(1),
  confidence: confidenceLevelSchema,
});

/** Vulnerability classes the curated CVE table is allowed to use. */
export const CURATED_VULN_CLASSES = [
  'remote-code-execution',
  'command-injection',
  'authentication-bypass',
  'buffer-overflow',
  'path-traversal',
  'information-disclosure',
  'denial-of-service',
] as const;

export const iotCveRefSchema = z.object({
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/, 'must be a well-formed CVE identifier'),
  vendor: z.string().min(1),
  product: z.string().min(1),
  classText: z.string().min(1),
  description: z.string().min(1),
  sources: z.array(referenceSourceSchema).min(1),
  confidence: confidenceLevelSchema,
});

export const iotMalwareDatasetRefSchema = z.object({
  name: z.string().min(1),
  url: z.string().url(),
  licence: z.string().min(1),
  description: z.string().min(1),
  format: z.string().min(1),
  malwareFamilies: z.array(z.string()),
  archScope: z.array(z.string()),
  knownLimitations: z.array(z.string()),
  potentialBias: z.array(z.string()),
  reproducibility: z.string().min(1),
});

/** A dataset row must not smuggle an identifier (e.g. a CWE) into free text. */
const IDENTIFIER_LIKE = /^(CWE|CVE)-\d+/i;

/**
 * Mirai and related IoT botnet families.
 *
 * The first entry is the original Mirai; the remaining entries are
 * well-documented derivatives or related IoT botnet families that are
 * routinely discussed in public reporting on the Mirai ecosystem.
 */
export const MIRAI_VARIANTS: MiraiVariantRef[] = [
  {
    name: 'Mirai',
    aliases: ['Mirai botnet'],
    firstSeen: '2016-09',
    summary:
      'Mirai is a Linux-based IoT botnet that emerged in 2016 and assembles a large army of ' +
      'compromised embedded devices (IP cameras, DVRs and home routers) by continuously scanning the ' +
      'internet for open Telnet services and logging in with a hard-coded list of common default ' +
      'credentials. Infected devices connect to command-and-control servers and are instructed to launch ' +
      'volumetric DDoS attacks. Its source code was released publicly in late 2016 and became the base ' +
      'for a long series of later variants.',
    notableTraits: [
      'Telnet default-credential brute force using a hard-coded ~62-entry credential dictionary',
      'Centralised command-and-control with a small command set (report, attack, etc.)',
      'Multi-architecture ELF payloads (ARM, MIPS, x86 and others)',
      'Source code released publicly in late 2016, spawning many derivatives',
    ],
    sources: [
      {
        title: 'CISA/US-CERT Alert (TA16-288A): Heightened DDoS Threat Posed by Mirai and Other Botnets',
        url: 'https://www.cisa.gov/news-events/alerts/2016/10/14/heightened-ddos-threat-posed-mirai-and-other-botnets',
      },
      {
        title: 'Cloudflare — What is the Mirai Botnet?',
        url: 'https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/',
      },
      {
        title: 'Cloudflare — Inside the infamous Mirai IoT Botnet: A Retrospective Analysis',
        url: 'https://blog.cloudflare.com/inside-mirai-the-infamous-iot-botnet-a-retrospective-analysis/',
      },
    ],
    confidence: 'confirmed',
  },
  {
    name: 'Satori',
    aliases: ['Satori', 'OKIRU/SATORI', 'Mirai Satori'],
    firstSeen: '2017-12',
    summary:
      'Satori is a Mirai-derived IoT botnet first observed in December 2017. Unlike the original Mirai it ' +
      'spreads primarily by exploiting router vulnerabilities rather than by credential brute force, ' +
      'notably CVE-2017-17215 in Huawei HG532 routers (TCP port 37215) and CVE-2014-8361 in the Realtek ' +
      'SDK miniigd UPnP SOAP service. It recruited a very large number of devices within hours of ' +
      'activation, and its source code was subsequently posted publicly, which accelerated the creation ' +
      'of further variants.',
    notableTraits: [
      'Vulnerability-based propagation instead of default-credential brute force',
      'Exploits Huawei HG532 (CVE-2017-17215) and Realtek SDK (CVE-2014-8361)',
      'Recruited hundreds of thousands of routers very rapidly',
      'Source code released publicly, spawning additional derivatives',
    ],
    sources: [
      {
        title: 'Trend Micro — Source Code of IoT Botnet Satori Publicly Released on Pastebin',
        url: 'https://www.trendmicro.com/vinfo/pl/security/news/internet-of-things/source-code-of-iot-botnet-satori-publicly-released-on-pastebin',
      },
      {
        title: 'Cloudflare — What is the Mirai Botnet?',
        url: 'https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/',
      },
      {
        title: 'Analyzing The Mirai IoT Botnet and Its Recent Variants (arXiv:2508.01909)',
        url: 'https://arxiv.org/pdf/2508.01909',
      },
    ],
    confidence: 'confirmed',
  },
  {
    name: 'Okiru',
    aliases: ['Okiru', 'Mirai Okiru'],
    firstSeen: '2018-01',
    summary:
      'Okiru is a Mirai-derived IoT botnet lineage first observed in early 2018. Its principal ' +
      'distinguishing characteristic is that it was built for additional CPU architectures, including ' +
      'ARC (Argonaut RISC Core) processors, extending the reach of the Mirai family beyond the ' +
      'ARM/MIPS/x86 targets of earlier builds. It is closely related to Satori, and the IoT-23 dataset ' +
      'uses "Okiru" as a traffic label for this family.',
    notableTraits: [
      'Compiled for additional CPU architectures, notably ARC',
      'Close code lineage to Satori',
      'Used as a labelled malware family in the IoT-23 dataset',
    ],
    sources: [
      {
        title: 'Cloudflare — What is the Mirai Botnet?',
        url: 'https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/',
      },
      {
        title: 'Analyzing The Mirai IoT Botnet and Its Recent Variants (arXiv:2508.01909)',
        url: 'https://arxiv.org/pdf/2508.01909',
      },
      {
        title: 'Stratosphere Laboratory — IoT-23 dataset (label definitions include "Okiru")',
        url: 'https://www.stratosphereips.org/datasets-iot23',
      },
    ],
    confidence: 'observed',
  },
  {
    name: 'Masuta',
    aliases: ['Masuta', 'PureMasuta', 'Mirai Masuta'],
    firstSeen: '2017',
    summary:
      'Masuta is a Mirai variant reported from 2017. It began as the Mirai code with an expanded ' +
      'credential list and later added a SOAP-based exploit for propagation. The closely related variant ' +
      'tracked as "PureMasuta" weaponised a D-Link HNAP vulnerability. Masuta and PureMasuta are ' +
      'documented by Cloudflare and Fortinet as descendants of the Mirai codebase.',
    notableTraits: [
      'Started as Mirai with an updated credential dictionary',
      'Later added SOAP-exploit-based propagation',
      'The PureMasuta derivative weaponised the D-Link HNAP bug',
    ],
    sources: [
      {
        title: 'Cloudflare — What is the Mirai Botnet?',
        url: 'https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/',
      },
      {
        title: 'Fortinet — Internet of Things: Battle of the Bots (RootedCon research deck)',
        url: 'https://filestore.fortinet.com/fortiguard/research/RootedCon-IoT-Battle-of-the-bots.pdf',
      },
    ],
    confidence: 'observed',
  },
  {
    name: 'Wicked',
    aliases: ['Wicked Mirai'],
    firstSeen: '2018',
    summary:
      'Wicked is a Mirai variant identified by FortiGuard Labs that integrates the Mirai DDoS engine ' +
      'with several additional exploits to compromise unpatched IoT devices. Fortinet reported that ' +
      'Wicked adds at least three exploits not present in the original Mirai build, illustrating how the ' +
      'released Mirai source code is routinely combined with new vulnerability exploits.',
    notableTraits: [
      'Adds at least three exploits over the base Mirai build',
      'Retains the Mirai DDoS attack engine',
    ],
    sources: [
      {
        title: 'Fortinet — Threat Landscape Report Q2 2018 (names the WICKED Mirai variant)',
        url: 'https://www.fortinet.com/content/dam/fortinet/assets/threat-reports/q2-2018-threat-landscape-report.pdf',
      },
    ],
    confidence: 'observed',
  },
  {
    name: 'Reaper (IoTroop)',
    aliases: ['Reaper', 'IoTroop', 'IoT_Reaper'],
    firstSeen: '2017-10',
    summary:
      'Reaper (also called IoTroop) is an IoT botnet first reported in October 2017. Its code shares ' +
      'aspects of the leaked Mirai framework, but its propagation relies on a broad set of known IoT ' +
      'vulnerabilities (for example D-Link DIR-600/DIR-850L routers, GoAhead-based IP cameras, Netgear ' +
      'ReadyNAS, Vacron NVRs and Linksys E1500/E2500 devices) rather than default credentials. Public ' +
      'reporting emphasised both its rapid growth and its vulnerability-exploitation focus.',
    notableTraits: [
      'Exploit-driven propagation across many router, camera and NVR vulnerabilities',
      'Shares code lineage with Mirai but replaces credential brute force',
      'Grew rapidly during late 2017',
    ],
    sources: [
      {
        title: 'Radware ERT Threat Alert — Reaper Botnet (October 2017)',
        url: 'https://www.radware.com/getattachment/Security/Threat-Advisories-and-Attack-Reports/1786/ERT-Alert-ReaperBotnet.pdf.aspx/?lang=en-US',
      },
      {
        title: 'Cloudflare — Inside the infamous Mirai IoT Botnet: A Retrospective Analysis',
        url: 'https://blog.cloudflare.com/inside-mirai-the-infamous-iot-botnet-a-retrospective-analysis/',
      },
    ],
    confidence: 'observed',
  },
  {
    name: 'Mukashi',
    aliases: ['Mukashi'],
    firstSeen: '2020-03',
    summary:
      'Mukashi is a Mirai variant identified in early 2020 that targets Zyxel NAS devices by exploiting ' +
      'the pre-authentication command-injection flaw CVE-2020-9054, in addition to attempting ' +
      'default-credential logins. It was reported shortly after the Zyxel vulnerability became public ' +
      'and was used to build a DDoS-capable botnet.',
    notableTraits: [
      'Exploits Zyxel NAS CVE-2020-9054 for propagation',
      'Still performs Mirai-style default-credential brute force',
      'DDoS-capable Mirai lineage',
    ],
    sources: [
      {
        title: 'Unit 42 — New Mirai Variant "Mukashi" exploits Zyxel NAS (CVE-2020-9054)',
        url: 'https://unit42.paloaltonetworks.jp/new-mirai-variant-mukashi/',
      },
      {
        title: 'Analyzing The Mirai IoT Botnet and Its Recent Variants (arXiv:2508.01909)',
        url: 'https://arxiv.org/pdf/2508.01909',
      },
    ],
    confidence: 'confirmed',
  },
  {
    name: 'Mozi',
    aliases: ['Mozi', 'Mozi botnet'],
    firstSeen: '2019-09',
    summary:
      'Mozi is an IoT botnet first observed in late 2019 that spreads via known IoT exploits and weak ' +
      'Telnet passwords and uses a peer-to-peer (DHT-based) command-and-control model instead of a ' +
      'central server. Its code overlaps with Mirai and its variants; between October 2019 and June 2020 ' +
      'it accounted for a very large share of observed IoT botnet traffic. It is best described as a ' +
      'related IoT botnet family that reuses Mirai-derived techniques rather than a direct fork of Mirai.',
    notableTraits: [
      'Peer-to-peer (DHT) command and control instead of a central C2',
      'Propagates via known exploits and weak Telnet passwords',
      'Code overlap with Mirai; dominated observed IoT botnet traffic in 2019-2020',
    ],
    sources: [
      {
        title: 'IBM X-Force — Botnet attack: Mozi mozied into town',
        url: 'https://www.ibm.com/cn-zh/think/x-force/botnet-attack-mozi-mozied-into-town',
      },
      {
        title: 'Bitdefender — Mozi Botnet Accounts for Most Traffic in Q1 2020',
        url: 'https://www.bitdefender.com/blog/hotforsecurity/mozi-botnet-accounts-traffic-q1-2020-new-research-shows/',
      },
      {
        title: 'Security Affairs — New Mozi P2P Botnet targets Netgear, D-Link, Huawei routers',
        url: 'https://securityaffairs.com/95608/malware/mozi-p2p-botnet.html',
      },
    ],
    confidence: 'observed',
  },
  {
    name: 'Gafgyt (Bashlite)',
    aliases: ['Gafgyt', 'Bashlite', 'Qbot', 'Lizkebab', 'Torlus'],
    firstSeen: '2014',
    summary:
      'Gafgyt (also known as Bashlite) is a Linux/IoT DDoS botnet family first observed in 2014, ' +
      'initially spreading via the ShellShock (Bash) vulnerability and later via Telnet credential ' +
      'brute force and IoT exploits. It predates Mirai and is a separate family, but the two are ' +
      'frequently discussed together and sometimes combined in joint Mirai/Gafgyt campaigns because ' +
      'both target IoT/Linux devices for DDoS.',
    notableTraits: [
      'Predates Mirai; first observed in 2014',
      'Originally spread via ShellShock, later via Telnet brute force and IoT exploits',
      'Source code leaked around 2015, leading to many variants',
      'Frequently deployed alongside Mirai for DDoS attacks',
    ],
    sources: [
      {
        title: 'NJCCIC — Bashlite (Gafgyt) threat profile',
        url: 'https://www.cyber.nj.gov/threat-landscape/malware/botnets/bashlite',
      },
      {
        title: 'Trend Micro — Into the Battlefield: A Security Guide to IoT Botnets',
        url: 'https://www.trendmicro.com/vinfo/tw/security/news/internet-of-things/into-the-battlefield-a-security-guide-to-iot-botnets',
      },
      {
        title: 'Unit 42 — New Mirai and Gafgyt IoT/Linux Botnet Campaigns',
        url: 'https://unit42.paloaltonetworks.com/unit42-finds-new-mirai-gafgyt-iotlinux-botnet-campaigns/',
      },
    ],
    confidence: 'confirmed',
  },
];

/**
 * IoT/embedded CVEs that are frequently referenced in IoT botnet reporting and
 * repeatedly reused by Mirai lineage malware for propagation.
 */
export const IOT_CVES: IotCveRef[] = [
  {
    cve: 'CVE-2017-17215',
    vendor: 'Huawei',
    product: 'HG532 home router',
    classText: 'remote-code-execution',
    description:
      'Huawei HG532 routers (some customized versions) contain a remote code execution vulnerability ' +
      'reachable on TCP port 37215 through the UPnP/TR-064 DeviceUpgrade service. Sending crafted ' +
      'packets to /ctrlt/DeviceUpgrade_1 leads to arbitrary command execution. Disclosed by Check Point ' +
      'Research and exploited by the Satori/Okiru Mirai variant and later Mirai-derived botnets.',
    sources: [
      { title: 'NVD — CVE-2017-17215', url: 'https://nvd.nist.gov/vuln/detail/CVE-2017-17215' },
      {
        title: 'Trend Micro — Source Code of IoT Botnet Satori Publicly Released on Pastebin',
        url: 'https://www.trendmicro.com/vinfo/pl/security/news/internet-of-things/source-code-of-iot-botnet-satori-publicly-released-on-pastebin',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2018-10561',
    vendor: 'Dasan (GPON home routers)',
    product: 'GPON home router web interface',
    classText: 'authentication-bypass',
    description:
      'GPON home routers (Dasan-sourced firmware shipped by multiple ISPs) allow authentication bypass ' +
      'by appending "?images" to a URL path, granting unauthenticated access to administrative pages. ' +
      'It is listed in CISA\'s Known Exploited Vulnerabilities catalog and is used by IoT botnets when ' +
      'chained with CVE-2018-10562.',
    sources: [
      { title: 'NVD — CVE-2018-10561', url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-10561' },
      {
        title: 'Tellabs — Vulnerability statement CVE-2018-10561 and CVE-2018-10562',
        url: 'https://kb.tellabs.com/cve-2018-10561-and-cve-2018-10562',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2018-10562',
    vendor: 'Dasan (GPON home routers)',
    product: 'GPON home router web interface',
    classText: 'command-injection',
    description:
      'GPON home routers contain a command injection flaw in the diagnostic (ping/diag) functionality ' +
      'of the web management interface. Chained with the authentication bypass CVE-2018-10561, an ' +
      'unauthenticated attacker can execute arbitrary commands. It is listed in CISA\'s Known Exploited ' +
      'Vulnerabilities catalog and has been used by botnets including Satori.',
    sources: [
      { title: 'NVD — CVE-2018-10562', url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-10562' },
      {
        title: 'Juniper/safeguard — CVE-2018-10562: Dasan GPON Routers Command Injection (KEV)',
        url: 'https://www.safeguard.sh/resources/blog/cve-2018-10562-dasan-gigabit-passive-optical-network-gpon-routers-kev',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2014-8361',
    vendor: 'Realtek',
    product: 'SDK (miniigd UPnP SOAP service)',
    classText: 'remote-code-execution',
    description:
      'The miniigd SOAP service in the Realtek SDK allows remote attackers to execute arbitrary code ' +
      'via a crafted NewInternalClient request, typically reachable on TCP port 52869. It has been ' +
      'widely exploited by Mirai and its variants in the wild through at least 2023.',
    sources: [
      { title: 'NVD — CVE-2014-8361', url: 'https://nvd.nist.gov/vuln/detail/CVE-2014-8361' },
      {
        title: 'Unit 42 — Home & Small Office Wireless Routers Exploited to Attack Gaming Servers',
        url: 'https://unit42.paloaltonetworks.com/home-small-office-wireless-routers-exploited-to-attack-gaming-servers/',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2016-10372',
    vendor: 'Eir',
    product: 'D1000 modem',
    classText: 'command-injection',
    description:
      'The Eir D1000 modem does not properly restrict the TR-064 protocol, allowing remote attackers ' +
      'to execute arbitrary commands via TCP port 7547 (for example using the NewNTPServer feature). ' +
      'It was exploited in 2016 by a customized Mirai variant targeting DSL routers.',
    sources: [
      { title: 'NVD — CVE-2016-10372', url: 'https://nvd.nist.gov/vuln/detail/CVE-2016-10372' },
      {
        title: 'Radware ERT Threat Alert — New IoT Threat: DSL Routers Enslaving Attempt (December 2016)',
        url: 'https://www.radware.com/getattachment/Security/Threat-Advisories-and-Attack-Reports/1310/Radware-ERT-Alert-DT-Routers-Enslaving-Attempt.pdf.aspx/?lang=en-US',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2016-6277',
    vendor: 'NETGEAR',
    product: 'multiple router models',
    classText: 'command-injection',
    description:
      'Multiple NETGEAR router models allow unauthenticated command injection through the web ' +
      'management interface (for example /cgi-bin/;COMMAND), enabling arbitrary OS command execution ' +
      'with root privileges. It is listed in CISA\'s Known Exploited Vulnerabilities catalog and has ' +
      'been exploited by IoT botnets including Mirai and Gafgyt.',
    sources: [
      {
        title: 'CERT/CC — Multiple Netgear routers vulnerable to arbitrary command injection (VU#582384)',
        url: 'https://kb.cert.org/vuls/id/582384',
      },
      { title: 'NVD — CVE-2016-6277', url: 'https://nvd.nist.gov/vuln/detail/CVE-2016-6277' },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2016-20017',
    vendor: 'D-Link',
    product: 'DSL-2750B',
    classText: 'command-injection',
    description:
      'D-Link DSL-2750B devices before firmware 1.05 allow remote unauthenticated command injection ' +
      'via the "cli" parameter of login.cgi, as exploited in the wild from 2016 through 2022. It was ' +
      'used by the Satori Mirai variant for mass recruitment.',
    sources: [
      { title: 'NVD — CVE-2016-20017', url: 'https://nvd.nist.gov/vuln/detail/CVE-2016-20017' },
      {
        title: 'Rapid7 — D-Link DSL-2750B OS Command Injection (CVE-2016-20017)',
        url: 'https://www.rapid7.com/db/vulnerabilities/cve-2016-20017/',
      },
    ],
    confidence: 'confirmed',
  },
  {
    cve: 'CVE-2020-9054',
    vendor: 'Zyxel',
    product: 'NAS devices (firmware 5.21)',
    classText: 'command-injection',
    description:
      'Multiple Zyxel NAS devices running firmware 5.21 contain a pre-authentication command injection ' +
      'vulnerability in the weblogin.cgi executable. A crafted HTTP request to the username parameter ' +
      'allows an unauthenticated remote attacker to execute arbitrary code. It was exploited by the ' +
      'Mukashi Mirai variant in 2020.',
    sources: [
      { title: 'NVD — CVE-2020-9054', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-9054' },
      {
        title: 'Unit 42 — New Mirai Variant "Mukashi" exploits the Zyxel NAS vulnerability',
        url: 'https://unit42.paloaltonetworks.jp/new-mirai-variant-mukashi/',
      },
    ],
    confidence: 'confirmed',
  },
];

/**
 * Public research datasets useful for IoT malware traffic analysis, defensive
 * detection engineering and firmware research. URLs and licences were verified
 * against the publishing institutions at curation time.
 */
export const IOT_DATASETS: IotMalwareDatasetRef[] = [
  {
    name: 'IoT-23 (Aposemat IoT-23)',
    url: 'https://www.stratosphereips.org/datasets-iot23',
    licence: 'CC BY 4.0 (Zenodo record 4743746)',
    description:
      'Labelled network traffic from IoT devices: 20 captures of malware executed on real IoT hardware ' +
      'plus 3 captures of benign IoT device traffic, collected by the Stratosphere Laboratory (CTU ' +
      'University, Prague) and funded by Avast. Each capture includes the original PCAP and a Zeek ' +
      'conn.log with behaviour labels (Attack, DDoS, C&C, Mirai, Okiru, Torii, FileDownload, HeartBeat, ' +
      'PartOfAHorizontalPortScan, etc.).',
    format: 'PCAP + Zeek conn.log.labeled (labelled network flows)',
    malwareFamilies: ['Mirai', 'Okiru', 'Torii', 'Bashlite/Gafgyt'],
    archScope: ['ARM (Raspberry Pi infected devices)'],
    knownLimitations: [
      'Captures range from 2018 to 2019 and cover a limited set of malware families',
      'Malicious scenarios were executed on a small number of device types (mainly Raspberry Pi)',
      'Benign scenarios cover only three specific consumer devices',
    ],
    potentialBias: [
      'Single laboratory and network environment',
      'Funded and shaped by a single commercial sponsor (Avast)',
      'Malware families are those that were active during the capture window',
    ],
    reproducibility: 'Public download from Stratosphere/Zenodo with a citable DOI (10.5281/zenodo.4743746); no access gate.',
  },
  {
    name: 'CTU-13',
    url: 'https://www.stratosphereips.org/datasets-ctu13',
    licence: 'CC BY',
    description:
      'A labelled dataset of 13 captures that mix botnet, normal and background traffic, collected at ' +
      'CTU University in the Czech Republic by the Malware Capture Facility Project. It includes ' +
      'botnet traffic from families such as Neris, Rbot, Virut, Menti, Sogou, Murlo and NSIS.ay along ' +
      'with bidirectional NetFlow labels.',
    format: 'PCAP + bidirectional NetFlow with labels',
    malwareFamilies: ['Neris', 'Rbot', 'Virut', 'Menti', 'Sogou', 'Murlo', 'NSIS.ay'],
    archScope: ['x86/x86-64 (Windows hosts in a lab network)'],
    knownLimitations: [
      'Focused on Windows-era botnets rather than IoT/embedded malware',
      'Collected in a controlled university network',
    ],
    potentialBias: [
      'Lab-generated background traffic and a specific network topology',
      'Reflects the malware families active at capture time',
    ],
    reproducibility: 'Public download from Stratosphere with a documented CC BY licence.',
  },
  {
    name: 'Malware-Traffic-Analysis.net PCAP archive',
    url: 'https://www.malware-traffic-analysis.net/',
    licence: 'Free for educational / analysis use per site terms (attribution to the site)',
    description:
      'A long-running public collection of malware traffic analysis exercises, each shipping a ' +
      'password-protected ZIP of PCAPs (and often related artefacts) alongside a written analysis ' +
      'exercise. Widely used for hands-on network forensics and detection-engineering practice.',
    format: 'Password-protected ZIP archives containing PCAP files',
    malwareFamilies: ['Mixed — varies per exercise (not IoT-specific)'],
    archScope: ['x86/x86-64 (primarily Windows enterprise malware traffic)'],
    knownLimitations: [
      'Not IoT-specific; dominated by Windows/enterprise malware campaigns',
      'Archives are password protected and malware content varies widely between exercises',
      'No uniform label taxonomy across exercises',
    ],
    potentialBias: [
      'Curated by a single analyst',
      'Over-represents Windows enterprise threat campaigns relative to IoT botnets',
    ],
    reproducibility: 'Explicitly intended for download and re-analysis; exercises are archived over many years.',
  },
  {
    name: 'CIC-IDS2017',
    url: 'https://www.unb.ca/cic/datasets/ids-2017.html',
    licence: 'See CIC dataset terms (free for research with citation)',
    description:
      'An intrusion-detection evaluation dataset produced by the Canadian Institute for Cybersecurity ' +
      '(UNB) containing benign traffic and a range of attacks (DDoS, brute force, web attacks, botnet ' +
      'and port scanning) as PCAPs plus labelled flows generated with CICFlowMeter.',
    format: 'PCAP + labelled CSV flows (CICFlowMeter)',
    malwareFamilies: ['Generic botnet/attack traffic (DDoS, brute force, web attacks, scan)'],
    archScope: ['Mixed (synthetic test network of hosts and servers)'],
    knownLimitations: [
      'Traffic is synthetically generated in a lab, not captured from the wild',
      'Well-documented labelling and ground-truth issues affect some flows',
    ],
    potentialBias: [
      'Synthetic lab topology and attack generation',
      'Not tailored to IoT/embedded device behaviour',
    ],
    reproducibility: 'Public download from the CIC (UNB) website with a citation requirement.',
  },
  {
    name: 'CESNET-QUIC22',
    url: 'https://zenodo.org/records/7963302',
    licence: 'CC BY 4.0',
    description:
      'A large one-month dataset of QUIC network traffic flows from the CESNET2 backbone, published ' +
      'by CESNET (Czech Republic). It contains roughly 153 million network flows extended with ' +
      'features describing encrypted traffic, designed for encrypted-traffic classification research.',
    format: 'Flow feature records (CSV / columnar) with per-flow statistics',
    malwareFamilies: ['None — not a malware-labelled dataset'],
    archScope: ['N/A (backbone network flows)'],
    knownLimitations: [
      'No malware or attack labels; intended for protocol/application classification',
      'Not IoT-specific and anonymised/privacy-processed',
    ],
    potentialBias: [
      'Reflects a single national research and education network',
      'One-month collection window (four weeks in 2022)',
    ],
    reproducibility: 'Public download from Zenodo with a citable DOI and CC BY 4.0 licence.',
  },
  {
    name: 'CIC-YNU-IoTMal 2026',
    url: 'https://www.unb.ca/cic/datasets/ynu-iot-2026.html',
    licence: 'See CIC dataset terms (free for research with citation)',
    description:
      'A multilayer IoT malware dataset from the Canadian Institute for Cybersecurity (UNB) and Yunnan ' +
      'University that pairs static and dynamic analysis: network traffic (PCAP), one-second ' +
      'system-activity telemetry and system-call traces for a large set of IoT malware binaries ' +
      'executed across several CPU architectures.',
    format: 'PCAP + system-activity telemetry + system-call traces',
    malwareFamilies: ['Mixed IoT malware families (architecture-based execution set)'],
    archScope: ['ARM', 'MIPS', 'MIPSEL', 'x86'],
    knownLimitations: [
      'Very recent dataset; published baselines and evaluation pitfalls are still being characterised',
      'Malware executed in controlled virtual environments rather than on real devices',
    ],
    potentialBias: [
      'Samples sourced from a single malware-collection environment (IoTPOT)',
      'Execution environment shapes observed dynamic behaviour',
    ],
    reproducibility: 'Distributed via the CIC (UNB) datasets portal with a citation requirement.',
  },
  {
    name: 'N-BaIoT',
    url: 'https://archive.ics.uci.edu/dataset/442/detection+of+iot+botnet+attacks+n+baiot',
    licence: 'CC BY 4.0 (UCI Machine Learning Repository)',
    description:
      'Real traffic data gathered from nine commercial IoT devices authentically infected with Mirai ' +
      'and BASHLITE (Gafgyt). The dataset provides statistical feature records for benign operation ' +
      'and ten attack types carried out by the two botnets, and is a common benchmark for IoT ' +
      'anomaly/botnet detection.',
    format: 'CSV feature records (per-device statistical features)',
    malwareFamilies: ['Mirai', 'BASHLITE (Gafgyt)'],
    archScope: ['IoT consumer devices (cameras, doorbell, thermostat, etc.)'],
    knownLimitations: [
      'Feature-based (not raw packet captures) so payload-level analysis is not possible',
      'Covers only two botnet families and a small set of device models',
    ],
    potentialBias: [
      'Small number of specific device models in a lab setting',
      'Attack scripts were replayed by the researchers',
    ],
    reproducibility: 'Public, versioned dataset on the UCI Machine Learning Repository with a citable identifier.',
  },
  {
    name: 'BoT-IoT (UNSW Canberra)',
    url: 'https://research.unsw.edu.au/projects/bot-iot-dataset',
    licence: 'See UNSW dataset terms (free for research with citation)',
    description:
      'A botnet/IoT network forensic dataset created in the Cyber Range Lab of UNSW Canberra. It ' +
      'combines normal and botnet traffic covering DDoS/DoS, OS and service scans, keylogging and data ' +
      'exfiltration, provided as original PCAPs, Argus files and labelled CSVs.',
    format: 'PCAP + Argus flow files + labelled CSV',
    malwareFamilies: ['Generic botnet/attack traffic (DDoS/DoS, scan, keylogging, exfiltration)'],
    archScope: ['Mixed (simulated IoT network environment)'],
    knownLimitations: [
      'Simulated rather than wild-captured traffic',
      'Very imbalanced classes with an extremely high attack-to-benign ratio',
    ],
    potentialBias: [
      'Synthetic testbed topology and attack generation',
      'Attack scenarios designed by the dataset authors',
    ],
    reproducibility: 'Public download from UNSW with a citation requirement.',
  },
  {
    name: 'OWASP IoTGoat',
    url: 'https://github.com/OWASP/IoTGoat',
    licence: 'MIT',
    description:
      'A deliberately insecure firmware image built on OpenWrt and maintained by OWASP. It provides ' +
      'vulnerability challenges based on the OWASP IoT Top 10, making it a safe, self-contained target ' +
      'for firmware extraction, emulation and defensive testing practice.',
    format: 'Firmware image (OpenWrt-based, e.g. Raspberry Pi image) + source',
    malwareFamilies: ['None — intentionally vulnerable firmware for research'],
    archScope: ['ARM (Raspberry Pi build)', 'OpenWrt-supported targets'],
    knownLimitations: [
      'Deliberately vulnerable by design; not representative of production firmware',
      'Maintained as an educational target rather than a comprehensive firmware corpus',
    ],
    potentialBias: [
      'A single project-curated set of challenges',
      'Reflects the OWASP IoT Top 10 rather than the full space of real-world vulnerabilities',
    ],
    reproducibility: 'Public GitHub repository (MIT) with released firmware images.',
  },
  {
    name: 'OpenWrt firmware images',
    url: 'https://downloads.openwrt.org/',
    licence: 'GPL-2.0 (OpenWrt); individual packages may carry other licences',
    description:
      'Official OpenWrt firmware images published by the OpenWrt project for many router and embedded ' +
      'architectures. They are a widely used, freely redistributable reference for firmware extraction, ' +
      'filesystem analysis and emulation research.',
    format: 'Firmware images (e.g. sysupgrade/factory .bin, squashfs) per target',
    malwareFamilies: ['None — vendor/community firmware images'],
    archScope: ['Many (e.g. ARM, MIPS, MIPSEL, x86-64) depending on target'],
    knownLimitations: [
      'Images are legitimate OpenWrt builds, not vulnerability samples',
      'Target/device support varies and older targets are periodically dropped',
    ],
    potentialBias: [
      'Covers devices supported by OpenWrt, not the entire embedded firmware ecosystem',
      'Development snapshots are untested automated builds',
    ],
    reproducibility: 'Public download server with per-release target directories and checksums.',
  },
];

/** Summary counts for the curated datasets. */
export function datasetStats(): { variants: number; cves: number; datasets: number } {
  return {
    variants: MIRAI_VARIANTS.length,
    cves: IOT_CVES.length,
    datasets: IOT_DATASETS.length,
  };
}

/* ------------------------------------------------------------------------- */
/* Dataset consistency validation (§P2.2)                                    */
/* ------------------------------------------------------------------------- */

export type CuratedDatasetName = 'MIRAI_VARIANTS' | 'IOT_CVES' | 'IOT_DATASETS';

export interface CuratedDatasetIssue {
  dataset: CuratedDatasetName;
  index: number;
  key: string;
  field?: string;
  message: string;
}

export interface CuratedDatasetValidation {
  ok: boolean;
  issues: CuratedDatasetIssue[];
  counts: { variants: number; cves: number; datasets: number };
}

function collectIssues<T>(
  dataset: CuratedDatasetName,
  schema: z.ZodTypeAny,
  items: T[],
  keyOf: (item: T) => string,
  extra: (item: T, index: number) => CuratedDatasetIssue[] = () => [],
): CuratedDatasetIssue[] {
  const issues: CuratedDatasetIssue[] = [];
  const seen = new Set<string>();
  items.forEach((item, index) => {
    const key = keyOf(item);
    const parsed = schema.safeParse(item);
    if (!parsed.success) {
      for (const problem of parsed.error.issues) {
        issues.push({
          dataset,
          index,
          key,
          field: problem.path.join('.') || undefined,
          message: problem.message,
        });
      }
    }
    const normalized = key.trim().toLowerCase();
    if (seen.has(normalized)) {
      issues.push({ dataset, index, key, message: `duplicate key "${key}"` });
    } else {
      seen.add(normalized);
    }
    issues.push(...extra(item, index));
  });
  return issues;
}

/**
 * Cross-field consistency checks for a single curated CVE row.
 *
 * The failure mode this guards against is silent field drift — e.g. a row whose
 * narrative is about one component while `vendor`/`product` name another (the
 * "Log4j labelled as siemens / 6bk1602 firmware" class of bug). Nothing here is
 * repaired automatically; issues are reported so they can be reviewed against a
 * provenance source (§P2.2: never fix by guessing).
 */
export function cveConsistencyIssues(ref: IotCveRef, index = 0): CuratedDatasetIssue[] {
  const dataset: CuratedDatasetName = 'IOT_CVES';
  const issues: CuratedDatasetIssue[] = [];
  const push = (field: string, message: string): void => {
    issues.push({ dataset, index, key: ref.cve, field, message });
  };

  for (const field of ['vendor', 'product', 'classText'] as const) {
    if (IDENTIFIER_LIKE.test(ref[field])) {
      push(field, `field "${field}" contains an identifier, expected descriptive text`);
    }
  }
  if (!(CURATED_VULN_CLASSES as readonly string[]).includes(ref.classText)) {
    push('classText', `"${ref.classText}" is not a documented vulnerability class`);
  }
  if (!ref.sources.some((s) => /^https:\/\//i.test(s.url))) {
    push('sources', 'no HTTPS source reference for this record');
  }

  // The narrative must name the vendor or the product, otherwise the title and
  // the attribution can drift apart without anyone noticing.
  const narrative = ref.description.toLowerCase();
  const tokens = (value: string): string[] =>
    value
      .toLowerCase()
      .split(/[^a-z0-9.-]+/)
      .filter((w) => w.length > 2);
  const mentionsVendor = tokens(ref.vendor).some((w) => narrative.includes(w));
  const mentionsProduct = tokens(ref.product).some((w) => narrative.includes(w));
  if (!mentionsVendor && !mentionsProduct) {
    push(
      'description',
      `description names neither vendor "${ref.vendor}" nor product "${ref.product}"`,
    );
  }
  return issues;
}

/**
 * Validate every curated record against its schema and check cross-field
 * consistency (unique keys, primary provenance, CVE/class coherence).
 * Returns the full issue list — an empty list means the datasets are consistent.
 */
export function validateCuratedDatasets(): CuratedDatasetValidation {
  const variantIssues = collectIssues(
    'MIRAI_VARIANTS',
    miraiVariantRefSchema,
    MIRAI_VARIANTS,
    (v) => v.name,
  );
  const cveIssues = collectIssues('IOT_CVES', iotCveRefSchema, IOT_CVES, (c) => c.cve, cveConsistencyIssues);
  const datasetIssues = collectIssues(
    'IOT_DATASETS',
    iotMalwareDatasetRefSchema,
    IOT_DATASETS,
    (d) => d.name,
  );
  const issues = [...variantIssues, ...cveIssues, ...datasetIssues];
  return { ok: issues.length === 0, issues, counts: datasetStats() };
}
