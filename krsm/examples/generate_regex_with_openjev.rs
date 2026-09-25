use krsm::{AsyncRuntimeError, TaskTracker};
// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::Eq;
use std::collections::{HashMap, HashSet};
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
    /// Ask OpenJEV to pick a word from the paragraph text (by index)
    GenerateMatch(usize),
    /// Ask OpenJEV to check the list of matches is complete
    GenerateMatchFinalCheck(usize),
    /// Ask OpenJEV to pick a keyword that will cause auto skipping of paragraphs
    GenerateSkipKeyword(usize),
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
    GenerateMatch(Option<String>),
    GenerateMatchFinalCheck(bool),
    GenerateSkipKeyword(Option<String>),
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
            let future = RegexBuilderYieldReason::GenerateMatchFinalCheck(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;

            if RegexBuilderYieldResponse::GenerateMatchFinalCheck(true) == response {
                let mut result_list = self.curr_matches.borrow_mut();
                if result_list.len() > 0 {
                    let list = result_list.clone();
                    result_list.clear();
                    return Ok(list);
                }
            }

            let future = RegexBuilderYieldReason::GenerateMatch(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;
            let RegexBuilderYieldResponse::GenerateMatch(str) = response else {
                panic!("Invalid response for GenerateMatch");
            };
            if let Some(str) = &str {
                let mut result_list = self.curr_matches.borrow_mut();
                result_list.push(str.to_string());
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
            println!("Paragraph: {}", &paragraph);
            self.curr_paragraph.replace(paragraph.clone());
            let future = RegexBuilderYieldReason::FuzzyMatchesParagraph(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;
            if response == RegexBuilderYieldResponse::FuzzyMatchesParagraph(true) {
                let matches = self._generate_fuzzy_match().await?;
                has_match = true;

                println!("Matches: {:?}", &matches);

                let mut examples = self.known_examples.borrow_mut();
                examples.insert(paragraph.clone(), matches);
            }
            println!("");
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

        // First, wait for worker thread, and drain the completed & dropped tasks
        let Some(tracker) = maybe_tracker.take() else {
            if let Ok(tracker2) = receiver.try_recv() {
                maybe_tracker.replace(tracker2);
            }
            continue;
        };

        // Wait until all tracked tasks from previous worker batch are done
        if !tracker.sync(&runtime)? {
            maybe_tracker.replace(tracker);
            continue;
        }

        // Queue the new tasks AND start a new worker thread
        tracker.register_if(&runtime, |reason| match reason {
            RegexBuilderYieldReason::FuzzyMatchesParagraph(_) => true,
            RegexBuilderYieldReason::GenerateMatch(_) => true,
            RegexBuilderYieldReason::GenerateMatchFinalCheck(_) => true,
            _ => false,
        })?;

        let paragraph = { builder.curr_paragraph.borrow().clone() };
        let keyphrase = { builder.keyphrase.borrow().clone() };
        let matches = { builder.curr_matches.borrow().clone() };
        (sender, receiver) =
            channel::<TaskTracker<RegexBuilderYieldReason, RegexBuilderYieldResponse>>();
        std::thread::spawn(move || {
            if let Err(e) =
                tracker.work(|reason| worker_fn(reason, &paragraph, &keyphrase, &matches))
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

fn worker_fn(
    reason: RegexBuilderYieldReason,
    paragraph: &String,
    keyphrase: &String,
    matches: &Vec<String>,
) -> anyhow::Result<RegexBuilderYieldResponse> {
    let url = std::env::var("OPENJEV_URL")?;
    let key = std::env::var("OPENJEV_KEY")?;
    let key_header = format!("Bearer {}", key);

    let model = "openjev-latest";

    let words_set: HashSet<_> = paragraph.split(" ").collect();
    let words_list: Vec<_> = words_set.iter().take(50).collect();

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
        RegexBuilderYieldReason::GenerateMatch(_) => {
            let criteria: HashMap<_, _> = words_list
                .iter()
                .enumerate()
                .map(|(idx, str)| {
                    let criterion =
                        format!("{:?} would match meanings related to {:?}", str, keyphrase);
                    return (idx, criterion);
                })
                .collect();
            let body: OpenJevRequest<usize> = OpenJevRequest {
                state: paragraph.clone(),
                model: model.to_string(),
                questions: OpenJevQuestions {
                    item: OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Find a word from the above text that matches the following phrase: {:?}",
                            keyphrase
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
                            "We want to find all words matching the phrase {:?}. Please \
                            confirm that the following list is a complete of matches from the text: {:?}",
                            keyphrase, matches
                        ),
                        criteria: HashMap::from([
                            ('y', format!("Yes, this is a complete match: {:?}", matches)),
                            (
                                'n',
                                format!(
                                    "No, this is not complete. There are more matches than {:?}",
                                    matches
                                ),
                            ),
                        ]),
                    },
                },
            };
            request.with_json(&body)?.send()?
        }
        other => panic!("Unexpected task for worker thread: {:?}", other),
    };
    match reason {
        RegexBuilderYieldReason::FuzzyMatchesParagraph(_) => {
            let json: OpenJevResponse<char> = response.json()?;
            Ok(RegexBuilderYieldResponse::FuzzyMatchesParagraph(
                json.answers.item.choice == 'y',
            ))
        }
        RegexBuilderYieldReason::GenerateMatchFinalCheck(_) => {
            let json: OpenJevResponse<char> = response.json()?;
            Ok(RegexBuilderYieldResponse::GenerateMatchFinalCheck(
                json.answers.item.choice == 'y',
            ))
        }
        RegexBuilderYieldReason::GenerateMatch(_) => {
            let json: OpenJevResponse<String> = response.json()?;
            let idx: usize = json.answers.item.choice.parse().unwrap();
            Ok(RegexBuilderYieldResponse::GenerateMatch(Some(
                words_list[idx].to_string(),
            )))
        }
        other => panic!("Unexpected task for worker thread: {:?}", other),
    }
}
