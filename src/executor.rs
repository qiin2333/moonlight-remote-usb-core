use std::collections::{HashMap, HashSet};

use crate::pdu::{Reply, Request, SubmitReply, SubmitRequest, UnlinkReply};
use crate::{CoreError, CoreResult};

pub const USB_STATUS_NO_ENTRY: i32 = -2;
pub const USB_STATUS_CANCELLED: i32 = -104;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    pub status: i32,
    pub actual_length: u32,
    pub start_frame: i32,
    pub error_count: i32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorEvent {
    Submit {
        request_token: u64,
        request: SubmitRequest,
    },
    Cancel {
        request_token: u64,
        unlink_seqnum: u32,
    },
    Reply {
        pdu: Vec<u8>,
    },
}

#[derive(Debug)]
struct Pending {
    token: u64,
    request: SubmitRequest,
    unlink_seqnum: Option<u32>,
}

#[derive(Debug)]
pub struct Executor {
    max_inflight: usize,
    max_transfer_size: usize,
    next_token: u64,
    pending_by_sequence: HashMap<u32, Pending>,
    sequence_by_token: HashMap<u64, u32>,
    retired_tokens: HashSet<u64>,
}

impl Executor {
    pub fn new(max_inflight: usize, max_transfer_size: usize) -> CoreResult<Self> {
        if max_inflight == 0
            || max_inflight > 4096
            || max_transfer_size == 0
            || max_transfer_size > crate::pdu::MAX_TRANSFER_SIZE
        {
            return Err(CoreError::InvalidArgument);
        }
        Ok(Self {
            max_inflight,
            max_transfer_size,
            next_token: 1,
            pending_by_sequence: HashMap::with_capacity(max_inflight),
            sequence_by_token: HashMap::with_capacity(max_inflight),
            retired_tokens: HashSet::new(),
        })
    }

    #[must_use]
    pub fn inflight(&self) -> usize {
        self.pending_by_sequence.len()
    }

    pub fn accept_pdu(&mut self, wire: &[u8]) -> CoreResult<Vec<ExecutorEvent>> {
        match Request::decode(wire)? {
            Request::Submit(request) => self.accept_submit(request),
            Request::Unlink(request) => {
                if let Some(pending) = self.pending_by_sequence.get_mut(&request.target_seqnum) {
                    if pending.unlink_seqnum.is_some() {
                        return Err(CoreError::Duplicate);
                    }
                    pending.unlink_seqnum = Some(request.seqnum);
                    Ok(vec![ExecutorEvent::Cancel {
                        request_token: pending.token,
                        unlink_seqnum: request.seqnum,
                    }])
                } else {
                    Ok(vec![ExecutorEvent::Reply {
                        pdu: Reply::Unlink(UnlinkReply {
                            seqnum: request.seqnum,
                            status: USB_STATUS_NO_ENTRY,
                        })
                        .encode()?,
                    }])
                }
            }
        }
    }

    fn accept_submit(&mut self, request: SubmitRequest) -> CoreResult<Vec<ExecutorEvent>> {
        if request.transfer_buffer_length as usize > self.max_transfer_size {
            return Err(CoreError::LimitExceeded);
        }
        if self.pending_by_sequence.contains_key(&request.seqnum) {
            return Err(CoreError::Duplicate);
        }
        if self.pending_by_sequence.len() >= self.max_inflight {
            return Err(CoreError::WindowExhausted);
        }
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(CoreError::LimitExceeded)?;
        self.sequence_by_token.insert(token, request.seqnum);
        self.pending_by_sequence.insert(
            request.seqnum,
            Pending {
                token,
                request: request.clone(),
                unlink_seqnum: None,
            },
        );
        Ok(vec![ExecutorEvent::Submit {
            request_token: token,
            request,
        }])
    }

    pub fn complete(
        &mut self,
        request_token: u64,
        completion: Completion,
    ) -> CoreResult<Vec<ExecutorEvent>> {
        let Some(sequence) = self.sequence_by_token.remove(&request_token) else {
            if self.retired_tokens.contains(&request_token) {
                return Ok(Vec::new());
            }
            return Err(CoreError::NotFound);
        };
        let pending = self
            .pending_by_sequence
            .remove(&sequence)
            .ok_or(CoreError::Internal)?;
        self.remember_retired(request_token);
        let expected_data_length = match pending.request.direction {
            crate::pdu::Direction::In => completion.actual_length as usize,
            crate::pdu::Direction::Out => 0,
        };
        if completion.data.len() != expected_data_length
            || completion.actual_length > pending.request.transfer_buffer_length
        {
            return Err(CoreError::Malformed);
        }
        let mut events = vec![ExecutorEvent::Reply {
            pdu: Reply::Submit(SubmitReply {
                seqnum: pending.request.seqnum,
                direction: pending.request.direction,
                status: completion.status,
                actual_length: completion.actual_length,
                start_frame: completion.start_frame,
                error_count: completion.error_count,
                data: completion.data,
            })
            .encode()?,
        }];
        if let Some(unlink_seqnum) = pending.unlink_seqnum {
            events.push(ExecutorEvent::Reply {
                pdu: Reply::Unlink(UnlinkReply {
                    seqnum: unlink_seqnum,
                    status: 0,
                })
                .encode()?,
            });
        }
        Ok(events)
    }

    pub fn complete_cancel(
        &mut self,
        request_token: u64,
        unlink_status: i32,
    ) -> CoreResult<Vec<ExecutorEvent>> {
        let Some(sequence) = self.sequence_by_token.remove(&request_token) else {
            if self.retired_tokens.contains(&request_token) {
                return Ok(Vec::new());
            }
            return Err(CoreError::NotFound);
        };
        let pending = self
            .pending_by_sequence
            .remove(&sequence)
            .ok_or(CoreError::Internal)?;
        let unlink_seqnum = pending.unlink_seqnum.ok_or(CoreError::InvalidState)?;
        self.remember_retired(request_token);
        Ok(vec![
            ExecutorEvent::Reply {
                pdu: Reply::Submit(SubmitReply {
                    seqnum: pending.request.seqnum,
                    direction: pending.request.direction,
                    status: USB_STATUS_CANCELLED,
                    actual_length: 0,
                    start_frame: 0,
                    error_count: 0,
                    data: Vec::new(),
                })
                .encode()?,
            },
            ExecutorEvent::Reply {
                pdu: Reply::Unlink(UnlinkReply {
                    seqnum: unlink_seqnum,
                    status: unlink_status,
                })
                .encode()?,
            },
        ])
    }

    pub fn close(&mut self) -> CoreResult<Vec<ExecutorEvent>> {
        let tokens: Vec<u64> = self.sequence_by_token.keys().copied().collect();
        let mut events = Vec::with_capacity(tokens.len() * 2);
        for token in tokens {
            if let Ok(mut completion) = self.complete_cancel_for_close(token) {
                events.append(&mut completion);
            }
        }
        Ok(events)
    }

    fn complete_cancel_for_close(&mut self, token: u64) -> CoreResult<Vec<ExecutorEvent>> {
        let sequence = self
            .sequence_by_token
            .remove(&token)
            .ok_or(CoreError::NotFound)?;
        let pending = self
            .pending_by_sequence
            .remove(&sequence)
            .ok_or(CoreError::Internal)?;
        self.remember_retired(token);
        let mut events = vec![ExecutorEvent::Reply {
            pdu: Reply::Submit(SubmitReply {
                seqnum: pending.request.seqnum,
                direction: pending.request.direction,
                status: USB_STATUS_CANCELLED,
                actual_length: 0,
                start_frame: 0,
                error_count: 0,
                data: Vec::new(),
            })
            .encode()?,
        }];
        if let Some(unlink_seqnum) = pending.unlink_seqnum {
            events.push(ExecutorEvent::Reply {
                pdu: Reply::Unlink(UnlinkReply {
                    seqnum: unlink_seqnum,
                    status: USB_STATUS_CANCELLED,
                })
                .encode()?,
            });
        }
        Ok(events)
    }

    fn remember_retired(&mut self, token: u64) {
        if self.retired_tokens.len() >= self.max_inflight * 2 {
            self.retired_tokens.clear();
        }
        self.retired_tokens.insert(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Direction, UnlinkRequest};

    fn submit(seqnum: u32) -> SubmitRequest {
        SubmitRequest {
            seqnum,
            device_id: 1,
            direction: Direction::In,
            endpoint: 1,
            transfer_flags: 0,
            transfer_buffer_length: 8,
            start_frame: 0,
            interval: 0,
            setup: [0; 8],
            data: Vec::new(),
        }
    }

    #[test]
    fn unlink_emits_one_terminal_reply_and_ignores_late_completion() {
        let mut executor = Executor::new(4, 1024).unwrap();
        let event = executor
            .accept_pdu(&Request::Submit(submit(7)).encode().unwrap())
            .unwrap()
            .remove(0);
        let ExecutorEvent::Submit { request_token, .. } = event else {
            panic!("expected submit event");
        };
        let unlink = Request::Unlink(UnlinkRequest {
            seqnum: 8,
            device_id: 1,
            direction: Direction::In,
            endpoint: 1,
            target_seqnum: 7,
        });
        executor.accept_pdu(&unlink.encode().unwrap()).unwrap();
        let replies = executor.complete_cancel(request_token, 0).unwrap();
        assert_eq!(replies.len(), 2);
        assert!(
            executor
                .complete(
                    request_token,
                    Completion {
                        status: 0,
                        actual_length: 0,
                        start_frame: 0,
                        error_count: 0,
                        data: Vec::new(),
                    },
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn out_completion_reports_length_without_reply_payload() {
        let mut executor = Executor::new(4, 1024).unwrap();
        let mut request = submit(9);
        request.direction = Direction::Out;
        request.transfer_buffer_length = 4;
        request.data = vec![1, 2, 3, 4];
        let event = executor
            .accept_pdu(&Request::Submit(request).encode().unwrap())
            .unwrap()
            .remove(0);
        let ExecutorEvent::Submit { request_token, .. } = event else {
            panic!("expected submit event");
        };
        let reply = executor
            .complete(
                request_token,
                Completion {
                    status: 0,
                    actual_length: 4,
                    start_frame: 0,
                    error_count: 0,
                    data: Vec::new(),
                },
            )
            .unwrap()
            .remove(0);
        let ExecutorEvent::Reply { pdu } = reply else {
            panic!("expected reply event");
        };
        assert_eq!(pdu.len(), crate::pdu::HEADER_SIZE);
        let Reply::Submit(decoded) = Reply::decode(&pdu).unwrap() else {
            panic!("expected submit reply");
        };
        assert_eq!(decoded.direction, Direction::Out);
        assert_eq!(decoded.actual_length, 4);
        assert!(decoded.data.is_empty());
    }
}
