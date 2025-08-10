#[derive(Drop, Debug)]
pub enum IntelCrl {
    SgxPckPlatformCrl,
    SgxPckProcessorCrl,
    SgxRootCaCrl,
}

pub fn match_intel_crl(ref uri: Span<u8>) -> Option<IntelCrl> {
    // 'h'
    assert_next_char(ref uri, @0x68)?;
    // 't'
    assert_next_char(ref uri, @0x74)?;
    // 't'
    assert_next_char(ref uri, @0x74)?;
    // 'p'
    assert_next_char(ref uri, @0x70)?;
    // 's'
    assert_next_char(ref uri, @0x73)?;
    // ':'
    assert_next_char(ref uri, @0x3a)?;
    // '/'
    assert_next_char(ref uri, @0x2f)?;
    // '/'
    assert_next_char(ref uri, @0x2f)?;

    let char = uri.pop_front()?;
    if char == @0x63 {
        // 'c'

        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'f'
        assert_next_char(ref uri, @0x66)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'a'
        assert_next_char(ref uri, @0x61)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 'u'
        assert_next_char(ref uri, @0x75)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'd'
        assert_next_char(ref uri, @0x64)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 'v'
        assert_next_char(ref uri, @0x76)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'n'
        assert_next_char(ref uri, @0x6e)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'l'
        assert_next_char(ref uri, @0x6c)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'o'
        assert_next_char(ref uri, @0x6f)?;
        // 'm'
        assert_next_char(ref uri, @0x6d)?;
        // '/'
        assert_next_char(ref uri, @0x2f)?;
        // 'I'
        assert_next_char(ref uri, @0x49)?;
        // 'n'
        assert_next_char(ref uri, @0x6e)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'l'
        assert_next_char(ref uri, @0x6c)?;
        // 'S'
        assert_next_char(ref uri, @0x53)?;
        // 'G'
        assert_next_char(ref uri, @0x47)?;
        // 'X'
        assert_next_char(ref uri, @0x58)?;
        // 'R'
        assert_next_char(ref uri, @0x52)?;
        // 'o'
        assert_next_char(ref uri, @0x6f)?;
        // 'o'
        assert_next_char(ref uri, @0x6f)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'C'
        assert_next_char(ref uri, @0x43)?;
        // 'A'
        assert_next_char(ref uri, @0x41)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 'd'
        assert_next_char(ref uri, @0x64)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;

        // https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
        Some(IntelCrl::SgxRootCaCrl)
    } else if char == @0x61 {
        // 'a'

        // 'p'
        assert_next_char(ref uri, @0x70)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 'u'
        assert_next_char(ref uri, @0x75)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'd'
        assert_next_char(ref uri, @0x64)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 'v'
        assert_next_char(ref uri, @0x76)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'n'
        assert_next_char(ref uri, @0x6e)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'l'
        assert_next_char(ref uri, @0x6c)?;
        // '.'
        assert_next_char(ref uri, @0x2e)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'o'
        assert_next_char(ref uri, @0x6f)?;
        // 'm'
        assert_next_char(ref uri, @0x6d)?;
        // '/'
        assert_next_char(ref uri, @0x2f)?;
        // 's'
        assert_next_char(ref uri, @0x73)?;
        // 'g'
        assert_next_char(ref uri, @0x67)?;
        // 'x'
        assert_next_char(ref uri, @0x78)?;
        // '/'
        assert_next_char(ref uri, @0x2f)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'e'
        assert_next_char(ref uri, @0x65)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'f'
        assert_next_char(ref uri, @0x66)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'a'
        assert_next_char(ref uri, @0x61)?;
        // 't'
        assert_next_char(ref uri, @0x74)?;
        // 'i'
        assert_next_char(ref uri, @0x69)?;
        // 'o'
        assert_next_char(ref uri, @0x6f)?;
        // 'n'
        assert_next_char(ref uri, @0x6e)?;
        // '/'
        assert_next_char(ref uri, @0x2f)?;
        // 'v'
        assert_next_char(ref uri, @0x76)?;

        let char = uri.pop_front()?;
        // '3' or '4'
        if char != @0x33 && char != @0x34 {
            return None;
        }

        // '/'
        assert_next_char(ref uri, @0x2f)?;
        // 'p'
        assert_next_char(ref uri, @0x70)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'k'
        assert_next_char(ref uri, @0x6b)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'r'
        assert_next_char(ref uri, @0x72)?;
        // 'l'
        assert_next_char(ref uri, @0x6c)?;
        // '?'
        assert_next_char(ref uri, @0x3f)?;
        // 'c'
        assert_next_char(ref uri, @0x63)?;
        // 'a'
        assert_next_char(ref uri, @0x61)?;
        // '='
        assert_next_char(ref uri, @0x3d)?;
        // 'p'
        assert_next_char(ref uri, @0x70)?;

        let char = uri.pop_front()?;
        if char == @0x6c {
            // 'l'

            // 'a'
            assert_next_char(ref uri, @0x61)?;
            // 't'
            assert_next_char(ref uri, @0x74)?;
            // 'f'
            assert_next_char(ref uri, @0x66)?;
            // 'o'
            assert_next_char(ref uri, @0x6f)?;
            // 'r'
            assert_next_char(ref uri, @0x72)?;
            // 'm'
            assert_next_char(ref uri, @0x6d)?;

            // https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform
            // https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform
            Some(IntelCrl::SgxPckPlatformCrl)
        } else if char == @0x72 {
            // 'r'

            // 'o'
            assert_next_char(ref uri, @0x6f)?;
            // 'c'
            assert_next_char(ref uri, @0x63)?;
            // 'e'
            assert_next_char(ref uri, @0x65)?;
            // 's'
            assert_next_char(ref uri, @0x73)?;
            // 's'
            assert_next_char(ref uri, @0x73)?;
            // 'o'
            assert_next_char(ref uri, @0x6f)?;
            // 'r'
            assert_next_char(ref uri, @0x72)?;

            // https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor
            // https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor
            Some(IntelCrl::SgxPckProcessorCrl)
        } else {
            None
        }
    } else {
        None
    }
}

#[inline]
fn assert_next_char(ref chars: Span<u8>, char: @u8) -> Option<()> {
    if chars.pop_front()? == char {
        Some(())
    } else {
        None
    }
}
