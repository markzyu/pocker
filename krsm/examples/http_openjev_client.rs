// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::Eq;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::mpsc::channel;

/// This is an example of a HTTP client with business logics. It uses AIs like
/// OpenJEV to find semantic matches in any **English** text, given an input prompt.
///
/// This example doesn't implement the networking I/O logics and instead relies
/// on `minreq` to perform the actual I/O.
///
/// Each `YieldReason` here is just a http or an I/O request
///
/// The `YieldReason` would not carry query params. Instead, those are stored on
/// the state machine itself, in `HttpClient` struct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HttpClientYieldReason {
    /// Ask OpenJEV whether the paragraph is a match
    FuzzyMatchesParagraph(usize),
    /// Ask OpenJEV to pick a word from the paragraph text (by index)
    GenerateMatch(usize),
    /// Ask OpenJEV to check the list of matches is complete
    GenerateMatchFinalCheck(usize),
    /// Ask OpenJEV to pick a keyword that will cause auto skipping of paragraphs
    GenerateSkipKeyword(usize),
    /// Read a text file on disk and split paragraphs
    ReadFileIntoParagraphs(usize),
}

/// The id of an example is the paragraph content itself
type ExampleId = String;

/// The exact phrases that were identified by GenerateMatchFinalCheck
type ExampleAndMatch = Vec<String>;

/// maps the paragraph string to its list of known matches
type ExamplesAndMatches = HashMap<ExampleId, ExampleAndMatch>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HttpClientYieldResponse {
    FuzzyMatchesParagraph(bool),
    GenerateMatch(Option<String>),
    GenerateMatchFinalCheck(bool),
    GenerateSkipKeyword(Option<String>),
    ReadFileIntoParagraphs(Vec<String>),
}

type AsyncRuntime = krsm::AsyncRuntime<HttpClientYieldReason, HttpClientYieldResponse>;
type TaskTracker = krsm::TaskTracker<HttpClientYieldReason, HttpClientYieldResponse>;
type TaskBatch = krsm::TaskBatch<HttpClientYieldReason, HttpClientYieldResponse>;

/// This is a state machine that only yields when interacting with AI and with user input
/// Even though it has "async" syntax, it doesn't implement asyncio and instead relies on a worker thread.
///
/// Note: One potential future extension is to save entire copies of HttpClient states, and allow
///       user input to revert back to a past copy, and make manual corrections to AI outputs/trajectory
struct HttpClient<'a> {
    runtime: &'a AsyncRuntime,
    keyphrase: RefCell<String>,

    next_http_ticket: RefCell<usize>,

    curr_paragraph: RefCell<String>,
    curr_matches: RefCell<Vec<String>>,

    // Search path is currently both the parent search glob and the single file being searched
    // (We should distinguish the two eventually and allow users to change file selection)
    fuzzy_search_path: RefCell<PathBuf>,

    known_examples: RefCell<ExamplesAndMatches>,
}

type TResult<T> = Result<T, krsm::AsyncRuntimeError>;

impl<'a> HttpClient<'a> {
    fn new(runtime: &'a AsyncRuntime, keyphrase: String, path: PathBuf) -> Self {
        Self {
            runtime,
            keyphrase: RefCell::new(keyphrase),

            next_http_ticket: RefCell::new(0),

            curr_paragraph: RefCell::new(String::new()),
            curr_matches: RefCell::new(Vec::new()),

            fuzzy_search_path: RefCell::new(path),
            known_examples: RefCell::new(HashMap::new()),
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
            let future = HttpClientYieldReason::GenerateMatchFinalCheck(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;

            if HttpClientYieldResponse::GenerateMatchFinalCheck(true) == response {
                let mut result_list = self.curr_matches.borrow_mut();
                if result_list.len() > 0 {
                    let list = result_list.clone();
                    result_list.clear();
                    return Ok(list);
                }
            }

            let future = HttpClientYieldReason::GenerateMatch(self._ticket());
            let response = self.runtime.new_pending_future(future).await?;
            let HttpClientYieldResponse::GenerateMatch(str) = response else {
                panic!("Invalid response for GenerateMatch");
            };
            if let Some(str) = &str {
                let mut result_list = self.curr_matches.borrow_mut();
                result_list.push(str.to_string());
            }
        }
    }

    async fn fuzzy_scan_file(&self) -> TResult<&RefCell<ExamplesAndMatches>> {
        let response = self
            .runtime
            .new_pending_future(HttpClientYieldReason::ReadFileIntoParagraphs(
                self._ticket(),
            ))
            .await?;
        let HttpClientYieldResponse::ReadFileIntoParagraphs(paragraphs) = response else {
            panic!("Invalid response for ReadFileIntoParagraphs");
        };
        let mut skip_words: VecDeque<String> = VecDeque::new();
        for paragraph in paragraphs {
            let mut is_skip = false;
            for skip_word in &skip_words {
                let skip_word_lowercase = skip_word.trim().to_lowercase();
                let is_match = paragraph.to_lowercase().contains(&skip_word_lowercase);
                if skip_word_lowercase.len() > 2 && is_match {
                    println!("Skipping due to {:?}: {}", &skip_word_lowercase, &paragraph);
                    is_skip = true;
                    break;
                }
            }
            if is_skip {
                continue;
            }

            println!("Paragraph: {}", &paragraph);
            self.curr_paragraph.replace(paragraph.clone());
            let future1 = HttpClientYieldReason::FuzzyMatchesParagraph(self._ticket());
            let future2 = HttpClientYieldReason::GenerateSkipKeyword(self._ticket());
            let (response1, response2) = futures_lite::future::zip(
                self.runtime.new_pending_future(future1),
                self.runtime.new_pending_future(future2),
            )
            .await;
            if let HttpClientYieldResponse::GenerateSkipKeyword(word) = response2? {
                if let Some(word) = word {
                    if word.chars().all(char::is_alphanumeric) {
                        skip_words.push_back(word);
                    }
                    if skip_words.len() > 10 {
                        skip_words.pop_front();
                    }
                }
            }
            if response1? == HttpClientYieldResponse::FuzzyMatchesParagraph(true) {
                let matches = self._generate_fuzzy_match().await?;

                println!("\nMatches: {:?}\n", &matches);

                let mut examples = self.known_examples.borrow_mut();
                examples.insert(paragraph.clone(), matches);
            }
        }
        Ok(&self.known_examples)
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
struct OpenJevRequest<K: Hash + Eq> {
    state: String,
    model: String,
    questions: HashMap<String, OpenJevQuestion<K>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevAnswer<K: Hash + Eq> {
    choice: K,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenJevResponse<K: Hash + Eq> {
    answers: HashMap<String, OpenJevAnswer<K>>,
}

// --------------------------

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let keyphrase = args.next().unwrap_or_default();
    let pathstr = args.next().unwrap_or_default();
    let pathbuf = PathBuf::from(&pathstr);

    if keyphrase.trim().len() == 0 {
        println!("Missing keyphrase in cmdline, should be first arg");
        std::process::exit(1);
    }
    if pathstr.trim().len() == 0 {
        println!("Missing path in cmdline, should be second arg");
        std::process::exit(1);
    }

    let runtime = AsyncRuntime::new()?;
    let builder = HttpClient::new(&runtime, keyphrase, pathbuf);
    let mut future = builder.fuzzy_scan_file();

    // Two falsey states:
    //    - None means the worker thread is currently alive
    //    - Some(0) means the worker thread is done and there are no more tracked tasks
    let mut maybe_tracker: Option<TaskTracker> = Some(TaskTracker::new());

    #[allow(unused_assignments)]
    let (mut sender, mut receiver) = channel::<TaskTracker>();

    loop {
        let result = unsafe { runtime.run_async_step(&mut future)? };
        if let Some(examples) = result {
            println!("\nResults: {:?}", &examples?.borrow());
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
            HttpClientYieldReason::FuzzyMatchesParagraph(_) => true,
            HttpClientYieldReason::GenerateMatch(_) => true,
            HttpClientYieldReason::GenerateMatchFinalCheck(_) => true,
            HttpClientYieldReason::GenerateSkipKeyword(_) => true,
            HttpClientYieldReason::ReadFileIntoParagraphs(_) => true,
        })?;

        let paragraph = { builder.curr_paragraph.borrow().clone() };
        let keyphrase = { builder.keyphrase.borrow().clone() };
        let matches = { builder.curr_matches.borrow().clone() };
        let read_file = { builder.fuzzy_search_path.borrow().clone() };
        (sender, receiver) = channel::<TaskTracker>();
        std::thread::spawn(move || {
            let work_result = tracker.work_in_batches(4, |batch| {
                let words_set: HashSet<_> = paragraph.split(" ").collect();
                let words_list: Vec<_> =
                    words_set.iter().take(50).map(ToString::to_string).collect();

                // Handle std fs calls first
                std_fs_worker_fn(batch, &read_file)?;

                // Batch all http requests into a single API call
                let response =
                    http_request_batcher(batch, &paragraph, &keyphrase, &matches, &words_list)?;
                http_response_unbatcher(batch, response.as_ref(), &words_list)
            });
            if let Err(e) = work_result {
                println!("Worker thread failed due to {:?}", e);
                std::process::exit(2);
            }
            if let Err(e) = sender.send(tracker) {
                println!("Worker thread failed due to {:?}", e);
                std::process::exit(2);
            }
        });
    }
    Ok(())
}

fn http_request_batcher(
    batch: &mut TaskBatch,
    paragraph: &String,
    keyphrase: &String,
    matches: &Vec<String>,
    words_list: &Vec<String>,
) -> anyhow::Result<Option<minreq::Response>> {
    let url = std::env::var("OPENJEV_URL")?;
    let key = std::env::var("OPENJEV_KEY")?;
    let key_header = format!("Bearer {}", key);
    let model = "openjev-latest";

    let request = minreq::post(&url).with_header("Authorization", &key_header);
    let mut questions: HashMap<String, OpenJevQuestion<String>> = HashMap::new();
    for item in batch {
        let Some((reason, _)) = item else {
            continue;
        };
        match reason {
            HttpClientYieldReason::FuzzyMatchesParagraph(_) => {
                let y = "y".to_string();
                let n = "n".to_string();
                questions.insert(
                    "FuzzyMatchesParagraph".to_string(),
                    OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Does this text semantically mention the string: {:?}", keyphrase
                        ),
                        criteria: HashMap::from([
                            (y, "Semantically, allowing typos and other spellings, yes, this is a match".to_string()),
                            (n, "Semantically, allowing typos and other spellings, no, this is not a match".to_string())
                        ]),
                    }
                );
            }
            HttpClientYieldReason::GenerateMatch(_) => {
                let criteria: HashMap<_, _> = words_list
                    .iter()
                    .enumerate()
                    .map(|(idx, str)| {
                        let criterion =
                            format!("{:?} would match meanings related to {:?}", str, keyphrase);
                        return (idx.to_string(), criterion);
                    })
                    .collect();
                questions.insert(
                    "GenerateMatch".to_string(),
                    OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Find a word from the above text that matches the following phrase: {:?}",
                            keyphrase
                        ),
                        criteria,
                    },
                );
            }
            HttpClientYieldReason::GenerateMatchFinalCheck(_) => {
                let y = "y".to_string();
                let n = "n".to_string();
                questions.insert(
                    "GenerateMatchFinalCheck".to_string(),
                    OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "We want to find all words matching the phrase {:?}. Please \
                            confirm that the following list is a complete of matches from the text: {:?}",
                            keyphrase, matches
                        ),
                        criteria: HashMap::from([
                            (y, format!("Yes, this is a complete match: {:?}", matches)),
                            (
                                n,
                                format!(
                                    "No, this is not complete. There are more matches than {:?}",
                                    matches
                                ),
                            ),
                        ]),
                    },
                );
            }
            HttpClientYieldReason::GenerateSkipKeyword(_) => {
                let mut criteria: HashMap<_, _> = words_list
                    .iter()
                    .enumerate()
                    .map(|(idx, str)| {
                        let criterion = format!(
                            "{:?} would likely show up never be related to {:?}",
                            str, keyphrase
                        );
                        return (idx.to_string(), criterion);
                    })
                    .collect();
                criteria.insert(
                    words_list.len().to_string(),
                    format!(
                        "Such word does not exist. Many of these words are somewhat related: {:?}",
                        &words_list
                    ),
                );
                questions.insert(
                    "GenerateSkipKeyword".to_string(),
                    OpenJevQuestion {
                        r#type: "choice".to_string(),
                        instructions: format!(
                            "Find a word from the above text that is unlikely to match paragraphs related to: {:?}",
                            keyphrase
                        ),
                        criteria,
                    },
                );
            }
            _ => (),
        };
    }

    if questions.len() == 0 {
        return Ok(None);
    }
    let body: OpenJevRequest<String> = OpenJevRequest {
        state: paragraph.clone(),
        model: model.to_string(),
        questions,
    };
    Ok(Some(request.with_json(&body)?.send()?))
}

fn http_response_unbatcher(
    batch: &mut TaskBatch,
    response: Option<&minreq::Response>,
    words_list: &Vec<String>,
) -> anyhow::Result<()> {
    let Some(response) = response else {
        return Ok(());
    };

    let json: OpenJevResponse<String> = response.json()?;
    for item in batch {
        let Some((reason, result)) = item else {
            continue;
        };
        match reason {
            HttpClientYieldReason::FuzzyMatchesParagraph(_) => {
                result.replace(HttpClientYieldResponse::FuzzyMatchesParagraph(
                    &json.answers["FuzzyMatchesParagraph"].choice == "y",
                ));
            }
            HttpClientYieldReason::GenerateMatchFinalCheck(_) => {
                result.replace(HttpClientYieldResponse::GenerateMatchFinalCheck(
                    &json.answers["GenerateMatchFinalCheck"].choice == "y",
                ));
            }
            HttpClientYieldReason::GenerateMatch(_) => {
                let idx: usize = json.answers["GenerateMatch"].choice.parse().unwrap();
                result.replace(HttpClientYieldResponse::GenerateMatch(Some(
                    words_list[idx].to_string(),
                )));
            }
            HttpClientYieldReason::GenerateSkipKeyword(_) => {
                let idx: usize = json.answers["GenerateSkipKeyword"].choice.parse().unwrap();
                result.replace(HttpClientYieldResponse::GenerateSkipKeyword(
                    words_list.get(idx).map(ToString::to_string),
                ));
            }
            _ => (),
        }
    }
    Ok(())
}

fn std_fs_worker_fn(batch: &mut TaskBatch, read_path: &PathBuf) -> anyhow::Result<()> {
    // Handle response
    for item in batch {
        let Some((reason, result)) = item else {
            continue;
        };
        if let HttpClientYieldReason::ReadFileIntoParagraphs(_) = reason {
            let file = std::fs::File::open(read_path).unwrap();
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
            result.replace(HttpClientYieldResponse::ReadFileIntoParagraphs(paragraphs));
        }
    }
    Ok(())
}
