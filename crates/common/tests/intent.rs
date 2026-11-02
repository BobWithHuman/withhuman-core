use withhuman_common::intent::{IntentLine, split_intent};

#[test]
fn splits_the_leading_intent_line() {
    assert_eq!(
        split_intent("[의도] 로그인 버그 수정 (확신도: 높음)\n수정하겠습니다.\n"),
        Some(IntentLine {
            intent: "로그인 버그 수정 (확신도: 높음)",
            rest: "수정하겠습니다.\n",
        })
    );
    assert_eq!(
        split_intent("**[의도]** : 테스트 추가\r\n본문"),
        Some(IntentLine {
            intent: "테스트 추가",
            rest: "본문",
        })
    );
    assert_eq!(
        split_intent("[의도] 배포 스크립트 점검"),
        Some(IntentLine {
            intent: "배포 스크립트 점검",
            rest: "",
        })
    );
}

#[test]
fn ignores_text_without_a_leading_intent() {
    assert_eq!(split_intent("수정하겠습니다.\n[의도] 나중 줄\n"), None);
    assert_eq!(split_intent("[의도]\n본문"), None);
    assert_eq!(split_intent(""), None);
}
