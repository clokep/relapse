// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains the definitions of the "base" push rules.

use std::borrow::Cow;
use std::collections::HashMap;

use lazy_static::lazy_static;
use serde_json::Value;

use super::KnownCondition;
use crate::push::SetTweak;
use crate::push::TweakValue;
use crate::push::{Action, EventPropertyIsCondition, SimpleJsonValue};
use crate::push::{Condition, EventMatchTypeCondition};
use crate::push::{EventMatchCondition, EventMatchPatternType};
use crate::push::{EventPropertyIsTypeCondition, PushRule};

const HIGHLIGHT_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: None,
    other_keys: Value::Null,
});

const HIGHLIGHT_FALSE_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("highlight"),
    value: Some(TweakValue::Other(Value::Bool(false))),
    other_keys: Value::Null,
});

const SOUND_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("default"))),
    other_keys: Value::Null,
});

const RING_ACTION: Action = Action::SetTweak(SetTweak {
    set_tweak: Cow::Borrowed("sound"),
    value: Some(TweakValue::String(Cow::Borrowed("ring"))),
    other_keys: Value::Null,
});

pub const BASE_PREPEND_OVERRIDE_RULES: &[PushRule] = &[PushRule {
    rule_id: Cow::Borrowed("global/override/.m.rule.master"),
    priority_class: 5,
    conditions: Cow::Borrowed(&[]),
    actions: Cow::Borrowed(&[]),
    default: true,
    default_enabled: false,
}];

pub const BASE_APPEND_OVERRIDE_RULES: &[PushRule] = &[
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.suppress_notices"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("content.msgtype"),
                pattern: Cow::Borrowed("m.notice"),
            },
        ))]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.invite_for_me"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.member"),
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.membership"),
                pattern: Cow::Borrowed("invite"),
            })),
            Condition::Known(KnownCondition::EventMatchType(EventMatchTypeCondition {
                key: Cow::Borrowed("state_key"),
                pattern_type: Cow::Borrowed(&EventMatchPatternType::UserId),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.member_event"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.member"),
            },
        ))]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.is_user_mention"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(
            KnownCondition::ExactEventPropertyContainsType(EventPropertyIsTypeCondition {
                key: Cow::Borrowed(r"content.m\.mentions.user_ids"),
                value_type: Cow::Borrowed(&EventMatchPatternType::UserId),
            }),
        )]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.contains_display_name"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::ContainsDisplayName)]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.is_room_mention"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventPropertyIs(EventPropertyIsCondition {
                key: Cow::Borrowed(r"content.m\.mentions.room"),
                value: Cow::Owned(SimpleJsonValue::Bool(true)),
            })),
            Condition::Known(KnownCondition::SenderNotificationPermission {
                key: Cow::Borrowed("room"),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.roomnotif"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::SenderNotificationPermission {
                key: Cow::Borrowed("room"),
            }),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.body"),
                pattern: Cow::Borrowed("@room"),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.tombstone"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.tombstone"),
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Cow::Borrowed(""),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.reaction"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.reaction"),
            },
        ))]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.room.server_acl"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.server_acl"),
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Cow::Borrowed(""),
            })),
        ]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
    // We don't want to notify on edits *unless* the edit directly mentions a
    // user, which is handled above.
    PushRule {
        rule_id: Cow::Borrowed("global/override/.m.rule.suppress_edits"),
        priority_class: 5,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventPropertyIs(
            EventPropertyIsCondition {
                key: Cow::Borrowed(r"content.m\.relates_to.rel_type"),
                value: Cow::Owned(SimpleJsonValue::Str(Cow::Borrowed("m.replace"))),
            },
        ))]),
        actions: Cow::Borrowed(&[]),
        default: true,
        default_enabled: true,
    },
];

pub const BASE_APPEND_CONTENT_RULES: &[PushRule] = &[PushRule {
    rule_id: Cow::Borrowed("global/content/.m.rule.contains_user_name"),
    priority_class: 4,
    conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatchType(
        EventMatchTypeCondition {
            key: Cow::Borrowed("content.body"),
            pattern_type: Cow::Borrowed(&EventMatchPatternType::UserLocalpart),
        },
    ))]),
    actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_ACTION, SOUND_ACTION]),
    default: true,
    default_enabled: true,
}];

pub const BASE_APPEND_UNDERRIDE_RULES: &[PushRule] = &[
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.call"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.call.invite"),
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, RING_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.message"),
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.encrypted_room_one_to_one"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.encrypted"),
            })),
            Condition::Known(KnownCondition::RoomMemberCount {
                is: Some(Cow::Borrowed("2")),
            }),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, SOUND_ACTION, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.message"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.message"),
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.m.rule.encrypted"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[Condition::Known(KnownCondition::EventMatch(
            EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("m.room.encrypted"),
            },
        ))]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
    PushRule {
        rule_id: Cow::Borrowed("global/underride/.im.vector.jitsi"),
        priority_class: 1,
        conditions: Cow::Borrowed(&[
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("type"),
                pattern: Cow::Borrowed("im.vector.modular.widgets"),
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("content.type"),
                pattern: Cow::Borrowed("jitsi"),
            })),
            Condition::Known(KnownCondition::EventMatch(EventMatchCondition {
                key: Cow::Borrowed("state_key"),
                pattern: Cow::Borrowed("*"),
            })),
        ]),
        actions: Cow::Borrowed(&[Action::Notify, HIGHLIGHT_FALSE_ACTION]),
        default: true,
        default_enabled: true,
    },
];

lazy_static! {
    pub static ref BASE_RULES_BY_ID: HashMap<&'static str, &'static PushRule> =
        BASE_PREPEND_OVERRIDE_RULES
            .iter()
            .chain(BASE_APPEND_OVERRIDE_RULES.iter())
            .chain(BASE_APPEND_CONTENT_RULES.iter())
            .chain(BASE_APPEND_UNDERRIDE_RULES.iter())
            .map(|rule| { (&*rule.rule_id, rule) })
            .collect();
}
