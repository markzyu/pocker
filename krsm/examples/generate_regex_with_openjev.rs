use krsm::TaskTracker;
// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::mpsc::channel;

/// Reasons that can cause the finite state machine to transition between states
/// Note: The usize content is a ticket number for the http request to openjev
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum RegexBuilderYieldReason {
    FuzzyMatchesParagraph(usize),
    GenerateMatchByPrefix(usize),
    GenerateMatchFinalCheck(usize),
    GenerateRegex(usize),
    UserInputAddMatch,
    UserInputRejectMatch,
}

/// The id of an example is the paragraph content itself
type ExampleId = String;

/// The exact phrases that were identified by GenerateMatchFinalCheck
type ExampleAndMatch = Vec<String>;

/// maps the paragraph string to its list of known matches
type ExamplesAndMatches = HashMap<ExampleId, ExampleAndMatch>;

// 62 + 9 + 20 + 5 = 96 total choices for JEV
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum RegexResponse {
    RestartFromEmpty,
    // a-z A-Z 0-9
    AppendChar(char),
    // * ? + ( ) | ! . \\
    AppendRegexSymbol(char),
    AppendAnyDigit,
    AppendAnyWord,
    AppendAnyAlphanumeric,
    // 1-20
    Backspace(usize),
    Finish,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum RegexBuilderYieldResponse {
    FuzzyMatchesParagraph(bool),
    GenerateMatchByPrefix(Option<char>),
    GenerateMatchFinalCheck(bool),
    GenerateRegex(RegexResponse),
    // (example paragraph, matched text)
    UserInputAddMatch(String, String),
    // (example paragraph, matched text)
    UserInputRejectMatch(String, String),
}

type AsyncRuntime = krsm::AsyncRuntime<RegexBuilderYieldReason, RegexBuilderYieldResponse>;

/// This is a state machine that only yields when interacting with AI and with user input
/// Even though it has "async" syntax, it doesn't call fs and network syscalls through async
/// Note: One potential future extension is to save entire copies of RegexBuilder states, and allow
///       user input to revert back to a past copy, and make manual corrections to AI outputs/trajectory
#[allow(dead_code)]
struct RegexBuilder<'a> {
    runtime: &'a AsyncRuntime,
    keyphrase: RefCell<String>,

    next_http_ticket: RefCell<usize>,

    curr_paragraph: RefCell<String>,
    curr_matches: RefCell<Vec<String>>,
    curr_match: RefCell<String>,
    curr_regex: RefCell<String>,

    // Search path is currently both the parent search glob and the single file being searched
    // (We should distinguish the two eventually and allow users to change file selection)
    fuzzy_search_path: RefCell<PathBuf>,

    // this should contain user_examples as a subset
    known_examples: RefCell<ExamplesAndMatches>,

    // these should track user interactions separately
    user_examples: RefCell<ExamplesAndMatches>,
    anti_examples: RefCell<ExamplesAndMatches>,
}

type TResult<T> = Result<T, krsm::AsyncRuntimeError>;

impl<'a> RegexBuilder<'a> {
    fn new(runtime: &'a AsyncRuntime, keyphrase: String, path: PathBuf) -> Self {
        Self {
            runtime,
            keyphrase: RefCell::new(keyphrase),

            next_http_ticket: RefCell::new(0),

            curr_paragraph: RefCell::new(String::new()),
            curr_matches: RefCell::new(Vec::new()),
            curr_match: RefCell::new(String::new()),
            curr_regex: RefCell::new(String::new()),

            fuzzy_search_path: RefCell::new(path),
            known_examples: RefCell::new(HashMap::new()),
            user_examples: RefCell::new(HashMap::new()),
            anti_examples: RefCell::new(HashMap::new()),
        }
    }

    fn _ticket(&self) -> usize {
        let mut ticket = self.next_http_ticket.borrow_mut();
        let result = *ticket;
        *ticket = result + 1;
        result
    }

    /// The input paragraph must contain a fuzzy match
    async fn _generate_fuzzy_match(&self) -> TResult<Vec<String>> {
        loop {
            let is_complete = futures_lite::future::or(
                async {
                    let future = RegexBuilderYieldReason::GenerateMatchFinalCheck(self._ticket());
                    let response = self.runtime.new_pending_future(future).await?;
                    Ok(RegexBuilderYieldResponse::GenerateMatchFinalCheck(true) == response)
                },
                async {
                    let future = RegexBuilderYieldReason::GenerateMatchByPrefix(self._ticket());
                    let response = self.runtime.new_pending_future(future).await?;
                    let RegexBuilderYieldResponse::GenerateMatchByPrefix(c) = response else {
                        panic!("Invalid response for GenerateMatchByPrefix");
                    };
                    if let Some(c) = c {
                        let mut result = self.curr_match.borrow_mut();
                        result.push(c);
                    } else {
                        let mut result_list = self.curr_matches.borrow_mut();
                        let mut result = self.curr_match.borrow_mut();
                        result_list.push(result.clone());
                        result.clear();
                    }
                    Ok(false)
                },
            )
            .await?;

            if is_complete {
                let mut result_list = self.curr_matches.borrow_mut();
                let list = result_list.clone();
                result_list.clear();
                return Ok(list);
            }
        }
    }

    async fn fuzzy_scan_file(&self) -> TResult<bool> {
        let pathbuf = { self.fuzzy_search_path.borrow().clone() };
        let file = std::fs::File::open(&pathbuf).unwrap();
        let reader = BufReader::new(file);
        let mut paragraphs: Vec<String> = Vec::new();
        let mut paragraph = String::new();

        for line in reader.lines() {
            let line = line.unwrap();
            if line.trim().len() == 0 {
                if paragraph.trim().len() > 0 {
                    paragraphs.push(paragraph.clone());
                }
                paragraph.clear();
            } else {
                paragraph.push(' ');
                paragraph.push_str(&line.trim());
            }
        }

        let mut has_match = false;
        for paragraph in paragraphs {
            self.curr_paragraph.replace(paragraph.clone());
            let future = RegexBuilderYieldReason::FuzzyMatchesParagraph(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;
            if response == RegexBuilderYieldResponse::FuzzyMatchesParagraph(true) {
                let matches = self._generate_fuzzy_match().await?;
                has_match = true;

                println!("Paragraph: {}", &paragraph);
                println!("Matches: {:?}", &matches);
                println!("");

                let mut examples = self.known_examples.borrow_mut();
                examples.insert(paragraph.clone(), matches);
            }
        }
        Ok(has_match)
    }
}

// --------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevQuestion<K: Hash + Eq> {
    r#type: String,
    instructions: String,
    criteria: HashMap<K, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevQuestions<K: Hash + Eq> {
    item: OpenJevQuestion<K>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevRequest<K: Hash + Eq> {
    state: String,
    model: String,
    questions: OpenJevQuestions<K>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevAnswer<K: Hash + Eq> {
    choice: K,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevAnswers<K: Hash + Eq> {
    item: OpenJevAnswer<K>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevResponse<K: Hash + Eq> {
    answers: OpenJevAnswers<K>,
}

// --------------------------

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let keyphrase = args.next().unwrap_or_default();
    let pathstr = args.next().unwrap_or_default();
    let pathbuf = PathBuf::from(&pathstr);

    if keyphrase.trim().len() == 0 {
        println!("Missing keyphrase in cmdline, should be first arg");
    }
    if pathstr.trim().len() == 0 {
        println!("Missing path in cmdline, should be second arg");
    }

    let runtime = AsyncRuntime::new()?;
    let builder = RegexBuilder::new(&runtime, keyphrase, pathbuf);
    let mut future = builder.fuzzy_scan_file();

    // Two falsey states:
    //    - None means the worker thread is currently alive
    //    - Some(0) means the worker thread is done and there are no more tracked tasks
    let mut maybe_tracker: Option<TaskTracker<RegexBuilderYieldReason, RegexBuilderYieldResponse>> =
        Some(TaskTracker::new());

    #[allow(unused_assignments)]
    let (mut sender, mut receiver) =
        channel::<TaskTracker<RegexBuilderYieldReason, RegexBuilderYieldResponse>>();

    loop {
        let result = unsafe { runtime.run_async_step(&mut future)? };
        if let Some(_) = result {
            break;
        }

        // TODO: If there are pending user interactions, those reason must be handled first

        // First, wait for worker thread, and drain the completed tasks
        let Some(tracker) = maybe_tracker.take() else {
            if let Ok(tracker2) = receiver.try_recv() {
                maybe_tracker.replace(tracker2);
            }
            continue;
        };

        let completed_reason = runtime.check_pending_reasons(|x| {
            if let Some(x) = x {
                tracker.is_task_complete(&x)
            } else {
                false
            }
        })?;
        if let Some(reason) = completed_reason {
            let response = tracker.remove_completed(&reason).unwrap();
            runtime.unblock_futures(reason, response)?;
            maybe_tracker.replace(tracker);
            continue;
        }

        if tracker.len() > 0 {
            // We can't queue new tasks until we unblock the completed ones, one by one
            maybe_tracker.replace(tracker);
            continue;
        }

        // Queue the new tasks AND start a new worker thread
        let mut lowpri_reasons: Vec<RegexBuilderYieldReason> = Vec::new();
        runtime.check_pending_reasons(|reason| {
            if let Some(reason) = reason {
                lowpri_reasons.push(reason);
            }
            false
        })?;
        for reason in lowpri_reasons {
            match reason {
                RegexBuilderYieldReason::FuzzyMatchesParagraph(_) => tracker.register(reason)?,
                RegexBuilderYieldReason::GenerateMatchByPrefix(_) => tracker.register(reason)?,
                RegexBuilderYieldReason::GenerateMatchFinalCheck(_) => tracker.register(reason)?,
                _ => {}
            }
        }

        if tracker.len() == 0 {
            // This is unexpected: We didn't find any valid reason and the future is still blocked
            panic!("Cannot unblock async futures. It is stuck.");
        }

        let paragraph = { builder.curr_paragraph.borrow().clone() };
        let keyphrase = { builder.keyphrase.borrow().clone() };
        let curr_match = { builder.curr_match.borrow().clone() };
        let matches = { builder.curr_matches.borrow().clone() };
        (sender, receiver) =
            channel::<TaskTracker<RegexBuilderYieldReason, RegexBuilderYieldResponse>>();
        std::thread::spawn(move || {
            println!("DEBUG len={}", tracker.len());
            if let Err(e) = tracker
                .work(|reason| worker_fn(reason, &paragraph, &keyphrase, &curr_match, &matches))
            {
                panic!("Worker thread failed due to {:?}", e);
            }
            if let Err(e) = sender.send(tracker) {
                panic!("Worker thread failed due to {:?}", e);
            }
        });
    }
    Ok(())
}

const MATCH_LETTERS: &'static str = "abcdefghijlkmnopqrstuvwxyz";

fn worker_fn(
    reason: RegexBuilderYieldReason,
    paragraph: &String,
    keyphrase: &String,
    curr_match: &String,
    matches: &Vec<String>,
) -> anyhow::Result<RegexBuilderYieldResponse> {
    let url = std::env::var("OPENJEV_URL")?;
    let key = std::env::var("OPENJEV_KEY")?;
    let key_header = format!("Bearer {}", key);

    let model = "openjev-latest";
    println!("DEBUG: {:?}", reason);

    let request = minreq::post(&url).with_header("Authorization", &key_header);
    let response = match reason {
        RegexBuilderYieldReason::FuzzyMatchesParagraph(_) => {
            let body: OpenJevRequest<char> =  OpenJevRequest {
                state: paragraph.clone(),
                model: model.to_string(),
                questions: OpenJevQuestions {
                    item: OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Does this text semantically mention the string: {:?}", keyphrase
                        ),
                        criteria: HashMap::from([
                            ('y', "Semantically, allowing typos and other spellings, yes, this is a match".to_string()),
                            ('n', "Semantically, allowing typos and other spellings, no, this is not a match".to_string())
                        ]),
                    }
                }
            };
            request.with_json(&body)?.send()?
        }
        RegexBuilderYieldReason::GenerateMatchByPrefix(_) => {
            let criteria: HashMap<_, _> = MATCH_LETTERS
                .chars()
                .map(|chr| {
                    return (
                        chr,
                        format!(
                            "{}{}* would match meanings related to {:?}",
                            curr_match, chr, keyphrase
                        ),
                    );
                })
                .collect();
            let body: OpenJevRequest<char> = OpenJevRequest {
                state: paragraph.clone(),
                model: model.to_string(),
                questions: OpenJevQuestions {
                    item: OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "We are trying to create a wildcard query matching: {:?}. But it should not match \
                            the following phrases: {:?}. Please come up with a **new** wildcard:",
                            keyphrase, matches
                        ),
                        criteria,
                    },
                },
            };
            request.with_json(&body)?.send()?
        }
        RegexBuilderYieldReason::GenerateMatchFinalCheck(_) => {
            let body: OpenJevRequest<char> = OpenJevRequest {
                state: paragraph.clone(),
                model: model.to_string(),
                questions: OpenJevQuestions {
                    item: OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Please confirm the word {:?} shows up in the above text. And please \
                            confirm that it matches the following meaning: {:?}.",
                            matches, keyphrase
                        ),
                        criteria: HashMap::from([
                            (
                                'y',
                                format!(
                                    "Yes, {:?} shows up, is an English word, and is a match",
                                    curr_match
                                ),
                            ),
                            ('m', format!("No, {:?} does not show up", curr_match)),
                            ('n', format!("No, {:?} is not a match", curr_match)),
                            ('o', format!("No, {:?} is not a word", curr_match)),
                        ]),
                    },
                },
            };
            request.with_json(&body)?.send()?
        }
        other => panic!("Unexpected task for worker thread: {:?}", other),
    };
    let json: OpenJevResponse<char> = response.json()?;
    println!("DEBUG: {} --> {:?}", &paragraph, &json);
    match reason {
        RegexBuilderYieldReason::FuzzyMatchesParagraph(_) => Ok(
            RegexBuilderYieldResponse::FuzzyMatchesParagraph(json.answers.item.choice == 'y'),
        ),
        RegexBuilderYieldReason::GenerateMatchFinalCheck(_) => {
            Ok(RegexBuilderYieldResponse::GenerateMatchFinalCheck(
                curr_match.trim().len() > 0 && json.answers.item.choice == 'y',
            ))
        }
        RegexBuilderYieldReason::GenerateMatchByPrefix(_) => {
            let chr = json.answers.item.choice;
            Ok(RegexBuilderYieldResponse::GenerateMatchByPrefix(
                if paragraph.contains(chr) || paragraph.contains(&chr.to_uppercase().to_string()) {
                    Some(chr)
                } else {
                    None
                },
            ))
        }
        other => panic!("Unexpected task for worker thread: {:?}", other),
    }
}
