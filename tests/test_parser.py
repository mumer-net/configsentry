from configsentry.parser import parse

CONFIG = """\
hostname r1
!
banner motd ^C
line vty 0 4
 transport input telnet
^C
banner login #Authorized only#
interface GigabitEthernet1
 description uplink
 ip address 10.0.0.1 255.255.255.0
line vty 0 4
 transport input ssh
end
"""


def test_top_level_blocks_and_children():
    cfg = parse(CONFIG)
    assert [line.text for line in cfg.lines] == [
        "hostname r1",
        "banner motd",
        "banner login",
        "interface GigabitEthernet1",
        "line vty 0 4",
        "end",
    ]
    interface = cfg.find(r"^interface ")[0]
    assert [c.text for c in interface.children] == ["description uplink", "ip address 10.0.0.1 255.255.255.0"]


def test_banner_text_is_not_parsed_as_config():
    cfg = parse(CONFIG)
    vtys = cfg.find(r"^line vty")
    assert len(vtys) == 1  # the "line vty 0 4" inside the motd banner is ignored
    assert vtys[0].child(r"^transport input").text == "transport input ssh"
    assert "transport input telnet" in cfg.banners["motd"]
    assert cfg.banners["login"] == "Authorized only"


def test_line_numbers_point_at_the_original_text():
    cfg = parse(CONFIG)
    vty = cfg.find(r"^line vty")[0]
    assert CONFIG.split("\n")[vty.number - 1] == "line vty 0 4"
    assert vty.number == 11


def test_windows_line_endings():
    cfg = parse("line con 0\r\n exec-timeout 5 0\r\n")
    assert cfg.lines[0].child(r"^exec-timeout").text == "exec-timeout 5 0"
