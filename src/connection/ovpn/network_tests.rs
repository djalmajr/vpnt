use super::*;
fn pairs(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    [
        ("ifconfig_local", "10.81.0.2"),
        ("ifconfig_netmask", "255.255.255.0"),
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
#[test]
fn complete_environment_and_duplicates() {
    let c = from_env(&pairs(&[
        ("tun_mtu", "1500"),
        ("trusted_ip", "198.51.100.2"),
        ("route_network_1", "10.0.0.0"),
        ("route_netmask_1", "255.0.0.0"),
        ("route_network_2", "10.0.0.0"),
        ("route_netmask_2", "255.0.0.0"),
        ("foreign_option_1", "dhcp-option DNS 10.81.0.1"),
        ("foreign_option_2", "dhcp-option DOMAIN Example.TEST"),
        ("ifconfig_ipv6_local", "fd00::1"),
    ]))
    .unwrap();
    assert_eq!(c.address, Ipv4Addr::new(10, 81, 0, 2));
    assert_eq!(c.prefix, 24);
    assert_eq!(c.mtu, Some(1500));
    assert_eq!(
        c.routes,
        vec![Route {
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8
        }]
    );
    assert_eq!(c.dns_servers, vec![Ipv4Addr::new(10, 81, 0, 1)]);
    assert_eq!(c.dns_domains, vec!["example.test"]);
    assert_eq!(c.server, Some(Ipv4Addr::new(198, 51, 100, 2)));
}
#[test]
fn rejects_bad_networks() {
    assert_eq!(from_env(&[]), Err(NetworkError::MissingAddress));
    assert_eq!(
        from_env(&[
            ("ifconfig_local".into(), "10.0.0.1".into()),
            ("ifconfig_remote".into(), "10.0.0.2".into())
        ]),
        Err(NetworkError::UnsupportedTopology)
    );
    assert_eq!(
        from_env(&pairs(&[("ifconfig_netmask", "255.0.255.0")])),
        Err(NetworkError::InvalidAddress)
    );
    for (net, mask, error) in [
        ("10.0.0.1", "255.0.0.0", NetworkError::InvalidRoute),
        ("0.0.0.0", "0.0.0.0", NetworkError::DefaultRoute),
        ("0.0.0.0", "128.0.0.0", NetworkError::DefaultRoute),
        ("10.0.0.0", "254.0.0.0", NetworkError::DefaultRoute),
        (
            "198.51.100.0",
            "255.255.255.0",
            NetworkError::RouteCoversServer,
        ),
    ] {
        assert_eq!(
            from_env(&pairs(&[
                ("trusted_ip", "198.51.100.1"),
                ("route_network_1", net),
                ("route_netmask_1", mask)
            ])),
            Err(error)
        );
    }
    assert_eq!(
        from_env(&pairs(&[("route_network_257", "10.0.0.0")])),
        Err(NetworkError::TooLarge)
    );
    assert_eq!(
        from_env(&pairs(&[
            ("foreign_option_1", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_2", "dhcp-option DNS 10.0.0.2"),
            ("foreign_option_3", "dhcp-option DNS 10.0.0.3"),
            ("foreign_option_4", "dhcp-option DNS 10.0.0.4"),
            ("foreign_option_5", "dhcp-option DNS 10.0.0.5")
        ])),
        Err(NetworkError::InvalidDns)
    );
    assert_eq!(
        from_env(&pairs(&[(
            "foreign_option_1",
            "dhcp-option DOMAIN -bad.test"
        )])),
        Err(NetworkError::InvalidDns)
    );
    assert_eq!(from_env(&pairs(&[("tun_mtu", "575")])).unwrap().mtu, None);
}

#[test]
fn route_and_environment_bounds() {
    let mut data = pairs(&[]);
    for n in 1..=257 {
        data.push((format!("route_network_{n}"), "10.0.0.0".into()));
        data.push((format!("route_netmask_{n}"), "255.0.0.0".into()));
    }
    assert_eq!(from_env(&data), Err(NetworkError::TooLarge));
    let many = vec![("unknown".to_string(), "value".to_string()); 1025];
    assert_eq!(from_env(&many), Err(NetworkError::TooLarge));
}
