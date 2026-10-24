use withhuman_collector::highlight_intent;

#[test]
fn highlights_the_leading_intent_line() {
    assert_eq!(
        highlight_intent("[의도] 로그인 버그 수정 (확신도: 높음)\n수정하겠습니다.\n").as_deref(),
        Some("**[파악한 의도] → 로그인 버그 수정 (확신도: 높음)**\n수정하겠습니다.\n")
    );
    assert_eq!(
        highlight_intent("**[의도]** : 테스트 추가\r\n").as_deref(),
        Some("**[파악한 의도] → 테스트 추가**\r\n")
    );
    assert_eq!(
        highlight_intent("[의도] 배포 스크립트 점검").as_deref(),
        Some("**[파악한 의도] → 배포 스크립트 점검**")
    );
}

#[test]
fn leaves_other_deltas_alone() {
    assert_eq!(highlight_intent("수정하겠습니다.\n[의도] 나중 줄\n"), None);
    assert_eq!(highlight_intent("[의도]\n"), None);
    assert_eq!(highlight_intent(""), None);
}
