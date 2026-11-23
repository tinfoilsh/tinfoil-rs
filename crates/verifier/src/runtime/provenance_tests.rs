use super::tests::Random;
use super::*;

const DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const OTHER_DIGEST: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// A requirement of the second container of [`config`].
const GITHUB: &str = "    provenance:
      github:
        repository: tinfoilsh/inference
        repository_id: 902195777
        workflow: containers.yml
        ref: refs/tags/vllm-v*
";

/// A requirement in flow style, for a config that is written on few lines.
const FLOW: &str =
    "{github: {repository: a/b, repository_id: 7, workflow: w.yml, ref: refs/heads/main}}";

fn image() -> String {
    format!("ghcr.io/tinfoilsh/inference-vllm@sha256:{DIGEST}")
}

/// A config of two containers, the second with the given image and the
/// given lines after it.
fn config(image: &str, provenance: &str) -> String {
    format!(
        "cvm-version: 0.15.5\ncontainers:\n  - name: router\n    image: example.com/router@sha256:{OTHER_DIGEST}\n  - name: model\n    image: {image}\n{provenance}"
    )
}

fn requirement(
    container: &str,
    repository: &str,
    id: &str,
    workflow: &str,
    git_ref: &str,
) -> ContainerProvenance {
    ContainerProvenance {
        container: container.to_owned(),
        digest: DIGEST.to_owned(),
        repository: repository.to_owned(),
        repository_id: id.to_owned(),
        workflow: workflow.to_owned(),
        git_ref: git_ref.to_owned(),
    }
}

/// The requirement that [`GITHUB`] states of the container `container`.
fn required(container: &str) -> ContainerProvenance {
    requirement(
        container,
        "tinfoilsh/inference",
        "902195777",
        "containers.yml",
        "refs/tags/vllm-v*",
    )
}

/// The requirement that [`FLOW`] states of the container `container`.
fn flow(container: &str) -> ContainerProvenance {
    requirement(container, "a/b", "7", "w.yml", "refs/heads/main")
}

fn read(config: &str) -> Result<Vec<ContainerProvenance>, String> {
    container_provenance_from_config(config.as_bytes()).map_err(|error| error.to_string())
}

fn error(config: &str) -> String {
    read(config).unwrap_err()
}

/// The error of [`GITHUB`] with one text replaced by another.
fn replaced(old: &str, new: &str) -> String {
    assert!(GITHUB.contains(old));
    error(&config(&image(), &GITHUB.replacen(old, new, 1)))
}

/// Whether the YAML parser itself rejected the config.
fn is_syntax_error(config: &str) -> bool {
    error(config).starts_with("parsing config provenance: yaml: ")
}

#[test]
fn reads_the_requirement_of_a_container() {
    assert_eq!(read(&config(&image(), GITHUB)), Ok(vec![required("model")]));
    for absent in [
        "",
        "    provenance:\n",
        "    provenance: null\n",
        "    provenance: ~\n",
    ] {
        assert_eq!(read(&config(&image(), absent)), Ok(Vec::new()), "{absent}");
    }
    // Without a requirement, the image needs no digest.
    assert_eq!(
        read(&config("example.com/model:latest", "")),
        Ok(Vec::new())
    );

    let other = GITHUB
        .replace("containers.yml", "other.yaml")
        .replace("refs/tags/vllm-v*", "refs/heads/release/*");
    let two = format!(
        "{}  - name: third\n    image: \"example.com/third:v1@sha256:{DIGEST}\"\n{other}",
        config(&image(), GITHUB)
    );
    let third = requirement(
        "third",
        "tinfoilsh/inference",
        "902195777",
        "other.yaml",
        "refs/heads/release/*",
    );
    assert_eq!(read(&two), Ok(vec![required("model"), third]));

    for written in [
        format!(
            "containers: [{{name: model, image: '{}', provenance: {FLOW}}}]\n",
            image()
        ),
        format!(
            "{{\"containers\": [{{\"name\": \"model\", \"image\": \"{}\", \"provenance\": {{\"github\": {{\"repository\": \"a/b\", \"repository_id\": 7, \"workflow\": \"w.yml\", \"ref\": \"refs/heads/main\"}}}}}}]}}\n",
            image()
        ),
        format!(
            "containers:\n- \"name\": model\n  image: |-\n    {}\n  !!str provenance:\n    'github':\n      repository: \"a/b\"\n      repository_id: 7 # the repository\n      workflow: !custom w.yml\n      ref: >-\n        refs/heads/main\n",
            image()
        ),
    ] {
        assert_eq!(read(&written), Ok(vec![flow("model")]), "{written}");
    }
}

#[test]
fn a_requirement_that_cannot_be_read_in_full_is_an_error() {
    let image = image();
    let provenance = "containers[1].provenance";
    let github = "containers[1].provenance.github";
    let cases = [
        (
            "unknown kind of requirement",
            config(
                &image,
                "    provenance:\n      gitlab:\n        project: a/b\n",
            ),
            format!("{provenance} has unknown field \"gitlab\""),
        ),
        (
            "extra requirement",
            config(
                &image,
                &format!("{GITHUB}      require_signed_commits: true\n"),
            ),
            format!("{provenance} has unknown field \"require_signed_commits\""),
        ),
        (
            "extra detail",
            config(&image, &format!("{GITHUB}        environment: release\n")),
            format!("{github} has unknown field \"environment\""),
        ),
        (
            "empty requirement",
            config(&image, "    provenance: {}\n"),
            format!("{github} is required"),
        ),
        (
            "not a mapping",
            config(&image, "    provenance: tinfoilsh/inference\n"),
            format!("{provenance} must be a mapping"),
        ),
        (
            "a sequence",
            config(&image, "    provenance: [github]\n"),
            format!("{provenance} must be a mapping"),
        ),
        (
            "an empty string",
            config(&image, "    provenance: \"\"\n"),
            format!("{provenance} must be a mapping"),
        ),
        (
            "false",
            config(&image, "    provenance: false\n"),
            format!("{provenance} must be a mapping"),
        ),
        (
            "duplicate kind",
            config(&image, &format!("{GITHUB}      github: {{}}\n")),
            format!("{provenance} has duplicate field \"github\""),
        ),
        (
            "duplicate detail",
            config(&image, &format!("{GITHUB}        ref: refs/heads/main\n")),
            format!("{github} has duplicate field \"ref\""),
        ),
        (
            "duplicate detail in another style",
            config(
                &image,
                &format!("{GITHUB}        \"ref\": refs/heads/main\n"),
            ),
            format!("{github} has duplicate field \"ref\""),
        ),
        (
            "null kind",
            config(&image, "    provenance: {github: ~}\n"),
            format!("{github} must be a mapping"),
        ),
        (
            "null-tagged requirement",
            config(&image, &format!("    provenance: !!null {FLOW}\n")),
            format!("{provenance} must be a mapping"),
        ),
        (
            "null-tagged detail",
            config(
                &image,
                "    provenance:\n      github: !!null {repository: a/b, repository_id: 1, workflow: w.yml, ref: refs/tags/v1}\n",
            ),
            format!("{github} must be a mapping"),
        ),
        (
            "kind without details",
            config(&image, "    provenance: {github: {}}\n"),
            format!("{github}.repository \"\" must be owner/name"),
        ),
        (
            "merge key in a requirement",
            config(&image, &format!("{GITHUB}        <<: {{a: b}}\n")),
            format!("{github} has unknown field \"<<\""),
        ),
        (
            "null key in a requirement",
            config(&image, &format!("{GITHUB}      ~: x\n")),
            format!("{provenance} has unknown field \"~\""),
        ),
        (
            "sequence as a key",
            config(&image, &format!("{GITHUB}        ? [a]\n        : b\n")),
            format!("{github} has a key that is not a scalar"),
        ),
        (
            "sequence as a detail",
            config(
                &image,
                &GITHUB.replace("containers.yml", "[containers.yml]"),
            ),
            format!("{github}.workflow must be a scalar"),
        ),
        (
            "image without digest",
            config("ghcr.io/tinfoilsh/inference-vllm:latest", GITHUB),
            "containers[1].image must pin a SHA-256 digest to declare provenance".to_owned(),
        ),
        (
            "second document",
            config(&image, &format!("{GITHUB}---\ncontainers: []\n")),
            "config must contain exactly one YAML document".to_owned(),
        ),
    ];
    for (name, config, want) in cases {
        assert_eq!(error(&config), want, "{name}");
    }

    let owner = |repository: &str| format!("{github}.repository {repository:?} must be owner/name");
    assert_eq!(
        replaced("tinfoilsh/inference", "inference"),
        owner("inference")
    );
    assert_eq!(replaced("tinfoilsh/inference", "a/b/c"), owner("a/b/c"));
    assert_eq!(
        replaced("tinfoilsh/inference", "/inference"),
        owner("/inference")
    );
    assert_eq!(
        replaced("tinfoilsh/inference", "tinfoilsh/"),
        owner("tinfoilsh/")
    );
    assert_eq!(replaced("tinfoilsh/inference", "a/(b|c)"), owner("a/(b|c)"));
    assert_eq!(replaced("tinfoilsh/inference", "~"), owner(""));
    assert_eq!(
        replaced("        repository: tinfoilsh/inference\n", ""),
        owner("")
    );
    let workflow = |name: &str| format!("{github}.workflow {name:?} must be a workflow file name");
    for name in [
        "sub/containers.yml",
        "containers.yl",
        "containers.YML",
        ".yml",
        "containers",
        "123",
    ] {
        assert_eq!(replaced("containers.yml", name), workflow(name));
    }
    let pattern =
        |git_ref: &str| format!("{github}.ref {git_ref:?} must be a tag or branch ref pattern");
    for git_ref in [
        "refs/pull/*/merge",
        "refs/tags/v@refs/heads/main",
        "refs/tags/",
        "refs/heads//main",
        "refs/heads/main/",
        "refs/tags/v(1|2)",
        "refs/remotes/origin/main",
        "tags/v1",
        "main",
        "true",
    ] {
        assert_eq!(replaced("refs/tags/vllm-v*", git_ref), pattern(git_ref));
    }
    assert_eq!(
        replaced("        ref: refs/tags/vllm-v*\n", ""),
        pattern("")
    );
}

/// A trailing line break or other text around a value is part of the value.
#[test]
fn every_value_is_matched_as_a_whole() {
    let github = "containers[1].provenance.github";
    for (old, new, want) in [
        (
            "tinfoilsh/inference",
            "\"tinfoilsh/inference\\n\"",
            "repository \"tinfoilsh/inference\\n\" must be owner/name",
        ),
        (
            "tinfoilsh/inference",
            "\" tinfoilsh/inference\"",
            "repository \" tinfoilsh/inference\" must be owner/name",
        ),
        (
            "containers.yml",
            "\"containers.yml\\n\"",
            "workflow \"containers.yml\\n\" must be a workflow file name",
        ),
        // A literal block keeps its final line break.
        (
            "containers.yml",
            "|\n          containers.yml",
            "workflow \"containers.yml\\n\" must be a workflow file name",
        ),
        (
            "containers.yml",
            "containers.yml.sig",
            "workflow \"containers.yml.sig\" must be a workflow file name",
        ),
        (
            "refs/tags/vllm-v*",
            "\"refs/tags/vllm-v*\\n\"",
            "ref \"refs/tags/vllm-v*\\n\" must be a tag or branch ref pattern",
        ),
        (
            "refs/tags/vllm-v*",
            "\"x\\nrefs/tags/vllm-v*\"",
            "ref \"x\\nrefs/tags/vllm-v*\" must be a tag or branch ref pattern",
        ),
    ] {
        assert_eq!(replaced(old, new), format!("{github}.{want}"), "{new}");
    }

    let unpinned = "containers[1].image must pin a SHA-256 digest to declare provenance";
    for image in [
        format!("\"example.com/model@sha256:{DIGEST}\\n\""),
        format!("\"\\nexample.com/model@sha256:{DIGEST}\""),
        format!("|\n      example.com/model@sha256:{DIGEST}"),
        format!("example.com/model@sha256:{DIGEST}@sha256:{OTHER_DIGEST}"),
        format!("example.com/model@sha256:{DIGEST}ab"),
        format!("example.com/model@sha256:{}", &DIGEST[2..]),
        format!("example.com/model@sha256:{}", DIGEST.to_uppercase()),
        format!("example.com/model@sha512:{DIGEST}"),
        format!("example.com/model@v1@sha256:{DIGEST}"),
        format!("\"@sha256:{DIGEST}\""),
        format!("\"example.com/my model@sha256:{DIGEST}\""),
        format!("\"example.com/my\\tmodel@sha256:{DIGEST}\""),
        format!("\"example.com/my\\fmodel@sha256:{DIGEST}\""),
        format!("\"example.com/my\\rmodel@sha256:{DIGEST}\""),
        "~".to_owned(),
    ] {
        assert_eq!(error(&config(&image, GITHUB)), unpinned, "{image}");
    }
    assert_eq!(
        error(&config(&image(), GITHUB).replace(&format!("    image: {}\n", image()), "")),
        unpinned
    );
    // White space is what the pattern of an image name excludes, and no
    // other character but the separator of the digest.
    for image in [
        format!("\"example.com/my\\u00a0model:v1@sha256:{DIGEST}\""),
        format!("\"example.com/my\\vmodel@sha256:{DIGEST}\""),
        format!("m@sha256:{DIGEST}"),
    ] {
        assert_eq!(
            read(&config(&image, GITHUB)),
            Ok(vec![required("model")]),
            "{image}"
        );
    }
}

#[test]
fn a_requirement_has_length_bounds() {
    let read_with = |old: &str, new: &str| read(&config(&image(), &GITHUB.replacen(old, new, 1)));
    let repository =
        |length: usize| format!("tinfoilsh/{}", "a".repeat(length - "tinfoilsh/".len()));
    assert!(read_with("tinfoilsh/inference", &repository(140)).is_ok());
    assert!(
        read_with("tinfoilsh/inference", &repository(141))
            .unwrap_err()
            .ends_with("must be owner/name")
    );
    let workflow = |length: usize| format!("{}.yml", "a".repeat(length - ".yml".len()));
    assert!(read_with("containers.yml", &workflow(255)).is_ok());
    assert!(
        read_with("containers.yml", &workflow(256))
            .unwrap_err()
            .ends_with("must be a workflow file name")
    );
    let pattern = |length: usize| format!("refs/tags/{}", "*".repeat(length - "refs/tags/".len()));
    assert!(read_with("refs/tags/vllm-v*", &pattern(255)).is_ok());
    assert!(
        read_with("refs/tags/vllm-v*", &pattern(256))
            .unwrap_err()
            .ends_with("must be a tag or branch ref pattern")
    );
}

#[test]
fn the_repository_id_is_read_as_written_in_plain_decimal() {
    let read_with = |id: &str| read(&config(&image(), &GITHUB.replacen("902195777", id, 1)));
    for id in ["1", "7", "924941172", "999999999999999999"] {
        let mut want = required("model");
        want.repository_id = id.to_owned();
        assert_eq!(read_with(id), Ok(vec![want]), "{id}");
    }
    let mut want = required("model");
    want.repository_id = "7".to_owned();
    assert_eq!(read_with("! 7"), Ok(vec![want.clone()]));
    assert_eq!(read_with("7 # the repository"), Ok(vec![want.clone()]));
    assert_eq!(
        read(&format!(
            "id: &id 7\n{}",
            config(&image(), &GITHUB.replacen("902195777", "*id", 1))
        )),
        Ok(vec![want])
    );

    // YAML decoders disagree on every other spelling of an integer.
    let numeric =
        "containers[1].provenance.github.repository_id must be the repository's numeric ID";
    for (name, id) in [
        ("leading zero", "0902195777"),
        ("leading zero of an octal number", "0755"),
        ("hex", "0x35c66b01"),
        ("octal", "0o6561465401"),
        ("binary", "0b11"),
        ("sign", "+902195777"),
        ("grouped", "902_195_777"),
        ("float", "9.02195777e8"),
        ("whole float", "902195777.0"),
        ("fraction", "7.5"),
        ("exponent", "1e3"),
        ("double-quoted string", "\"902195777\""),
        ("single-quoted string", "'902195777'"),
        ("block scalar", "|-\n          902195777"),
        ("negative", "-902195777"),
        ("zero", "0"),
        ("too long", "9999999999999999999"),
        ("too long for no integer type", "1000000000000000000"),
        ("list", "[902195777]"),
        ("mapping", "{id: 902195777}"),
        ("integer tag", "!!int 902195777"),
        ("string tag", "!!str 902195777"),
        ("float tag", "!!float 902195777"),
        ("another tag", "!custom 902195777"),
        ("null", "~"),
        ("boolean", "true"),
        ("infinity", ".inf"),
    ] {
        assert_eq!(read_with(id), Err(numeric.to_owned()), "{name}");
    }
    assert_eq!(
        read(&format!(
            "id: &id '7'\n{}",
            config(&image(), &GITHUB.replacen("902195777", "*id", 1))
        )),
        Err(numeric.to_owned())
    );
    assert_eq!(replaced("        repository_id: 902195777\n", ""), numeric);
}

/// An anchored config, with a requirement, its parts and a whole container
/// to refer to.
fn anchors() -> String {
    format!(
        "x-requirement: &requirement\n  github: &github\n    repository: &repository tinfoilsh/inference\n    repository_id: &id 902195777\n    workflow: &workflow containers.yml\n    ref: &ref refs/tags/vllm-v*\nx-image: &image {}\nx-name: &name model\nx-null: &null ~\nx-list: &list [a]\nx-container: &container\n  name: model\n  image: *image\n  provenance: *requirement\nx-plain: &plain\n  name: plain\n  image: example.com/plain:latest\n",
        image()
    )
}

#[test]
fn an_alias_stands_for_the_node_that_it_names() {
    let anchors = anchors();
    for containers in [
        "containers:\n  - name: model\n    image: *image\n    provenance: *requirement\n",
        "containers:\n  - name: *name\n    image: *image\n    provenance:\n      github: *github\n",
        "containers:\n  - name: model\n    image: *image\n    provenance:\n      github:\n        repository: *repository\n        repository_id: *id\n        workflow: *workflow\n        ref: *ref\n",
        "containers:\n  - *container\n",
        "x-all: &all\n  - *container\ncontainers: *all\n",
    ] {
        assert_eq!(
            read(&format!("{anchors}{containers}")),
            Ok(vec![required("model")]),
            "{containers}"
        );
    }
    assert_eq!(
        read(&format!(
            "{anchors}containers:\n  - *container\n  - *plain\n  - *container\n"
        )),
        Ok(vec![required("model"), required("model")])
    );
    for none in [
        "containers:\n  - name: model\n    image: *image\n    provenance: *null\n",
        "containers:\n  - *null\n",
        "containers: *null\n",
    ] {
        assert_eq!(read(&format!("{anchors}{none}")), Ok(Vec::new()), "{none}");
    }
    // The alias names the anchor that came last before it.
    assert_eq!(
        read(&format!(
            "{anchors}x-again: &requirement {FLOW}\ncontainers:\n  - name: model\n    image: *image\n    provenance: *requirement\n"
        )),
        Ok(vec![flow("model")])
    );

    for (containers, want) in [
        (
            "containers:\n  - name: model\n    image: *image\n    provenance: *list\n",
            "containers[0].provenance must be a mapping",
        ),
        (
            "containers:\n  - name: model\n    image: *image\n    provenance: *container\n",
            "containers[0].provenance has unknown field \"name\"",
        ),
        (
            "containers:\n  - name: model\n    image: *image\n    provenance: &self\n      github: *self\n",
            "containers[0].provenance.github has unknown field \"github\"",
        ),
        (
            "containers:\n  - name: *list\n",
            "containers[0].name must be a scalar",
        ),
        (
            "containers:\n  - *name\n",
            "parsing config provenance: containers[0] must be a mapping",
        ),
        (
            "containers: &all [*all]\n",
            "parsing config provenance: containers[0] must be a mapping",
        ),
        (
            "containers: *container\n",
            "parsing config provenance: containers must be a sequence",
        ),
    ] {
        assert_eq!(
            error(&format!("{anchors}{containers}")),
            want,
            "{containers}"
        );
    }
    assert!(is_syntax_error(&format!(
        "{anchors}containers:\n  - provenance: *missing\n"
    )));
}

#[test]
fn a_merge_key_brings_the_members_that_a_container_does_not_state() {
    let anchors = anchors();
    let read = |containers: &str| read(&format!("{anchors}containers:\n{containers}"));
    let named = |name: &str| Ok(vec![required(name)]);
    assert_eq!(read("  - <<: *container\n"), named("model"));
    assert_eq!(read("  - !!merge <<: *container\n"), named("model"));
    assert_eq!(read("  - <<: *container\n    name: mine\n"), named("mine"));
    assert_eq!(read("  - name: mine\n    <<: *container\n"), named("mine"));
    assert_eq!(
        read("  - \"name\": mine\n    <<: *container\n"),
        named("mine")
    );
    assert_eq!(
        read("  - name: mine\n    image: *image\n    <<: {provenance: *requirement}\n"),
        named("mine")
    );
    assert_eq!(
        self::read(&format!(
            "{anchors}containers: [{{<<: *container, name: flow}}]\n"
        )),
        named("flow")
    );
    // What the container states itself comes first, a null too.
    assert_eq!(
        read("  - <<: *container\n    provenance: ~\n"),
        Ok(Vec::new())
    );
    assert_eq!(
        read(&format!("  - <<: *container\n    provenance: {FLOW}\n")),
        Ok(vec![flow("model")])
    );
    // Then the merged mappings in order, each before those that it merges.
    assert_eq!(read("  - <<: [*container, *plain]\n"), named("model"));
    assert_eq!(read("  - <<: [*container, *container]\n"), named("model"));
    assert_eq!(
        read("  - <<: [*plain, *container]\n").unwrap_err(),
        "containers[0].image must pin a SHA-256 digest to declare provenance"
    );
    assert_eq!(read("  - <<: *plain\n"), Ok(Vec::new()));
    assert_eq!(
        read("  - <<: [{name: first, <<: *container}, {name: second}]\n"),
        named("first")
    );
    assert_eq!(
        read("  - <<: [{<<: *container}, {provenance: ~}]\n"),
        named("model")
    );
    assert_eq!(
        read("  - <<: [{provenance: ~}, {<<: *container}]\n"),
        Ok(Vec::new())
    );
    assert_eq!(
        read("  - <<: {provenance: ~, <<: *container}\n"),
        Ok(Vec::new())
    );
    // A quoted key and a member below a container are not merge keys.
    assert_eq!(
        read(
            "  - name: quoted\n    image: *image\n    \"<<\": *container\n    env:\n      <<: *container\n"
        ),
        Ok(Vec::new())
    );

    let mapping =
        "parsing config provenance: a merge key requires a mapping or a sequence of mappings";
    for value in [
        "x",
        "~",
        "*list",
        "*name",
        "[*container, x]",
        "[[*container]]",
        "{<<: ~}",
    ] {
        assert_eq!(
            read(&format!("  - name: model\n    <<: {value}\n")).unwrap_err(),
            mapping,
            "{value}"
        );
    }
    let repeated = "parsing config provenance: a container key is already defined";
    assert_eq!(
        read("  - <<: *container\n    <<: *plain\n").unwrap_err(),
        repeated
    );
    assert_eq!(
        read("  - <<: *container\n    \"<<\": *plain\n").unwrap_err(),
        repeated
    );
    assert_eq!(
        read("  - name: model\n    <<: {provenance: ~, provenance: ~}\n").unwrap_err(),
        repeated
    );
    // A member that the container states is not read from a merged mapping.
    assert_eq!(
        read("  - name: model\n    <<: {name: [a]}\n"),
        Ok(Vec::new())
    );
    assert_eq!(
        read("  - <<: {name: [a]}\n").unwrap_err(),
        "containers[0].name must be a scalar"
    );
    let contains = "parsing config provenance: a merge key names a mapping that contains it";
    assert_eq!(
        read("  - &self\n    name: model\n    <<: *self\n").unwrap_err(),
        contains
    );
    assert_eq!(
        read("  - &self\n    name: model\n    <<: [*self]\n").unwrap_err(),
        contains
    );
    assert_eq!(
        read("  - &outer\n    <<: &inner\n      <<: *outer\n").unwrap_err(),
        contains
    );
}

#[test]
fn constructs_that_would_need_interpreting_are_refused() {
    let anchors = anchors();
    let image = image();
    let merge = "parsing config provenance: merge keys are not supported at the top level";
    assert_eq!(
        error(&format!("{anchors}<<: {{containers: [*container]}}\n")),
        merge
    );
    assert_eq!(
        error(&format!(
            "{anchors}<<: {{a: b}}\ncontainers:\n  - *container\n"
        )),
        merge
    );
    assert_eq!(
        error(&format!(
            "{anchors}x-key: &key containers\n*key :\n  - *container\n"
        )),
        "parsing config provenance: a top-level key cannot be an alias"
    );
    assert_eq!(
        error(&format!(
            "{anchors}x-key: &key provenance\ncontainers:\n  - name: model\n    image: *image\n    *key : *requirement\n"
        )),
        "parsing config provenance: a container key must be a scalar"
    );
    assert_eq!(
        error(&format!(
            "{anchors}x-key: &github github\ncontainers:\n  - name: model\n    image: *image\n    provenance:\n      *github : *github\n"
        )),
        "containers[0].provenance has a key that is not a scalar"
    );

    for tagged in [
        config(&image, "    provenance: !!null ~\n"),
        config(&image, "    provenance: !!null absent\n"),
        config(
            &image,
            &GITHUB.replace("    provenance:", "    !!binary cHJvdmVuYW5jZQ==:"),
        ),
        config(&image, &GITHUB.replace("workflow:", "!!binary workflow:")),
        config(&image, &GITHUB.replace("ref:", "!!int ref:")),
        config(
            &image,
            &GITHUB.replace(
                "tinfoilsh/inference",
                "!!binary dGluZm9pbHNoL2luZmVyZW5jZQ==",
            ),
        ),
        config(&image, GITHUB).replace("name: model", "name: !!binary bW9kZWw="),
        config(&image, GITHUB).replace("name: model", "name: !!int 5"),
        config(&image, GITHUB).replace("name: model", "!!int 5: x\n    name: model"),
        config(&image, GITHUB).replace("name: router", "name: !<tag:yaml.org,2002:float> 5"),
        config(&format!("!!binary {image}"), GITHUB),
        "containers: !!null ~\n".to_owned(),
        "!!null containers: []\n".to_owned(),
        format!(
            "{anchors}x-tagged: &tagged {{!!bool true: x}}\ncontainers:\n  - <<: [*container, *tagged]\n"
        ),
    ] {
        let message = error(&tagged);
        assert!(
            message.ends_with("is not supported where container provenance is read"),
            "{tagged}: {message}"
        );
    }

    // A mapping of a requirement under a tag other than the mapping tag is
    // not read as one, and never as the absence of a requirement.
    for (tagged, want) in [
        ("    provenance: !!null", "containers[1].provenance"),
        ("    provenance: !!str", "containers[1].provenance"),
        ("    provenance: !!seq", "containers[1].provenance"),
        ("    provenance: !custom", "containers[1].provenance"),
        (
            "    provenance: !<tag:yaml.org,2002:null>",
            "containers[1].provenance",
        ),
        ("      github: !!null", "containers[1].provenance.github"),
        ("      github: !custom", "containers[1].provenance.github"),
    ] {
        let untagged = tagged.rsplit_once(' ').unwrap().0;
        assert_eq!(
            error(&config(&image, &GITHUB.replace(untagged, tagged))),
            format!("{want} must be a mapping"),
            "{tagged}"
        );
    }
    assert_eq!(
        error(&format!(
            "{anchors}x-tagged: &tagged !!null {FLOW}\ncontainers:\n  - name: model\n    image: *image\n    provenance: *tagged\n"
        )),
        "containers[0].provenance must be a mapping"
    );

    // A tag that names no scalar type leaves the text as written, the
    // mapping tag leaves a mapping one, a tag on a sequence or on a
    // container is ignored, and none of this applies to what is not read.
    for accepted in [
        config(&image, GITHUB).replace("name: model", "name: !!str model"),
        config(&image, GITHUB).replace("name: model", "name: !custom model"),
        config(
            &image,
            &GITHUB.replace("    provenance:", "    !!str provenance:"),
        ),
        config(
            &image,
            &GITHUB.replace("    provenance:", "    provenance: !!map"),
        ),
        config(
            &image,
            &GITHUB.replace("      github:", "      github: !<tag:yaml.org,2002:map>"),
        ),
        config(&image, GITHUB).replace("containers:\n", "containers: !!seq\n"),
        config(&image, GITHUB).replace("  - name: model", "  - !!null\n    name: model"),
        config(
            &image,
            &format!("{GITHUB}    env: !!binary YQ==\n    ports: {{!!int 1: b}}\n"),
        ),
        format!(
            "x-other: {{!!int 1: !!binary YQ==}}\n{}",
            config(&image, GITHUB)
        ),
    ] {
        assert_eq!(read(&accepted), Ok(vec![required("model")]), "{accepted}");
    }
}

#[test]
fn a_config_is_one_document_holding_a_mapping_or_nothing() {
    let empty = "parsing config provenance: the config is empty";
    assert_eq!(error(""), empty);
    assert_eq!(error("# nothing\n"), empty);
    for none in [
        "---\n",
        "~\n",
        "cvm-version: 0.15.5\n",
        "containers:\n",
        "containers: ~\n",
        "containers: []\n",
        "containers:\n  - ~\n  -\n",
        "containers:\n  - {}\n",
        "Containers:\n  - provenance: unread\n",
        "~:\n  - provenance: unread\n",
        "other:\n  containers:\n    - provenance: unread\n",
    ] {
        assert_eq!(read(none), Ok(Vec::new()), "{none}");
    }
    let mapping = "parsing config provenance: the config must be a mapping";
    assert_eq!(error("containers\n"), mapping);
    assert_eq!(error("- containers: []\n"), mapping);
    let sequence = "parsing config provenance: containers must be a sequence";
    for containers in ["x", "5", "\"\"", "{name: model}"] {
        assert_eq!(
            error(&format!("containers: {containers}\n")),
            sequence,
            "{containers}"
        );
    }
    let container = "parsing config provenance: containers[0] must be a mapping";
    for item in ["model", "[model]", "\"\""] {
        assert_eq!(
            error(&format!("containers:\n  - {item}\n")),
            container,
            "{item}"
        );
    }
    for second in ["---\n", "--- x\n", "---\ncontainers: []\n"] {
        assert_eq!(
            error(&format!("{}{second}", config(&image(), GITHUB))),
            "config must contain exactly one YAML document"
        );
    }
    let ended = format!("---\n{}...\n# end\n", config(&image(), GITHUB));
    assert_eq!(read(&ended), Ok(vec![required("model")]));
    let marked = format!("\u{feff}{}", config(&image(), GITHUB));
    assert_eq!(read(&marked), Ok(vec![required("model")]));

    // A null item is no container, so the ones after it are not counted
    // from it.
    assert_eq!(
        error(&format!(
            "containers:\n  - ~\n  - name: model\n    image: {}\n    provenance: {{}}\n",
            image()
        )),
        "containers[0].provenance.github is required"
    );
}

#[test]
fn the_keys_that_are_read_are_scalars_that_do_not_repeat() {
    let top = "parsing config provenance: a top-level mapping key is already defined";
    assert_eq!(error("containers: []\ncontainers: []\n"), top);
    assert_eq!(error("containers: []\n\"containers\": []\n"), top);
    assert_eq!(error("a: 1\na: 2\n"), top);
    assert_eq!(
        error("containers: []\n? [a]\n: b\n"),
        "parsing config provenance: a top-level key must be a scalar"
    );
    let repeated = "parsing config provenance: a container key is already defined";
    assert_eq!(error("containers:\n  - name: a\n    name: b\n"), repeated);
    assert_eq!(error("containers:\n  - name: a\n    'name': b\n"), repeated);
    assert_eq!(error("containers:\n  - env: 1\n    env: 2\n"), repeated);
    let scalar = "parsing config provenance: a container key must be a scalar";
    assert_eq!(
        error("containers:\n  - name: a\n    ? [x]\n    : y\n"),
        scalar
    );
    assert_eq!(error("containers:\n  - ? {x: 1}\n    : y\n"), scalar);
    for (member, value) in [("name", "[a]"), ("name", "{a: b}"), ("image", "{a: b}")] {
        assert_eq!(
            error(&format!("containers:\n  - {member}: {value}\n")),
            format!("containers[0].{member} must be a scalar")
        );
    }
    // Keys that differ in their text are different keys, a key that is not
    // one of the members that are read names nothing, and a repeat below a
    // container is not this module's to judge.
    for accepted in [
        "    1: a\n    0x1: b\n",
        "    ~: a\n    null: b\n",
        "    Provenance: unread\n    PROVENANCE: unread\n",
        "    env: {A: 1, A: 2}\n",
    ] {
        assert_eq!(
            read(&config(&image(), &format!("{GITHUB}{accepted}"))),
            Ok(vec![required("model")]),
            "{accepted}"
        );
    }
}

#[test]
fn a_name_is_the_text_of_its_scalar() {
    for (written, name) in [
        ("model", "model"),
        ("\"mod\\nel\"", "mod\nel"),
        ("123", "123"),
        ("0x10", "0x10"),
        ("true", "true"),
        ("~", ""),
        ("", ""),
        ("mod\n      el", "mod el"),
        ("|\n      model", "model\n"),
    ] {
        let config = config(&image(), GITHUB).replace("name: model", &format!("name: {written}"));
        assert_eq!(read(&config), Ok(vec![required(name)]), "{written}");
    }
    let unnamed = config(&image(), GITHUB).replace("  - name: model\n    image", "  - image");
    assert_eq!(read(&unnamed), Ok(vec![required("")]));
}

/// What makes a general YAML decoder panic or give up is an error here.
#[test]
fn a_malformed_config_is_an_error() {
    let good = config(&image(), GITHUB);
    for malformed in [
        "? [a]\n: 1\n<<: {b: 2}\ncontainers: []\n".to_owned(),
        "<<: {b: 2}\n? [a]\n: 1\n".to_owned(),
        "? {a: 1}\n: 1\n<<: {b: 2}\n".to_owned(),
        format!("{good}x: [\n"),
        format!("{good}   y: 1\n  z: 2\n"),
        format!("{good}x: \"unterminated\n"),
        format!("{good}x: *missing\n"),
        format!("{good}\u{feff}x: y\n"),
    ] {
        let message = error(&malformed);
        assert!(
            message.starts_with("parsing config provenance: "),
            "{malformed}: {message}"
        );
    }
    assert_eq!(
        container_provenance_from_config(&[good.as_bytes(), b"# \xff\n"].concat())
            .unwrap_err()
            .to_string(),
        "parsing config provenance: the config is not UTF-8"
    );
    for line_break in ['\u{85}', '\u{2028}', '\u{2029}'] {
        // Read with the character as a line break, the requirement is a
        // member of the container. Read with it as text, it is a comment.
        let two_readings = config(&image(), &format!("    # c{line_break}{GITHUB}"));
        assert_eq!(
            error(&two_readings),
            "parsing config provenance: the config contains a line break other than a line feed or a carriage return"
        );
    }
    let carriage_returns = good.replace('\n', "\r\n");
    assert_eq!(read(&carriage_returns), Ok(vec![required("model")]));
}

#[test]
fn a_config_has_size_and_depth_bounds() {
    let good = config(&image(), GITHUB);
    let padded = |size: usize| {
        let mut data = good.clone().into_bytes();
        data.resize(size, b'\n');
        data
    };
    assert_eq!(
        container_provenance_from_config(&padded(MAX_CONFIG_SIZE)),
        Ok(vec![required("model")])
    );
    assert_eq!(
        container_provenance_from_config(&padded(MAX_CONFIG_SIZE + 1))
            .unwrap_err()
            .to_string(),
        "parsing config provenance: the config is larger than 1048576 bytes"
    );
    let block = |depth: usize| format!("{good}a:\n {}x\n", "- ".repeat(depth));
    assert_eq!(read(&block(9_998)), Ok(vec![required("model")]));
    assert_eq!(
        error(&block(10_001)),
        "parsing config provenance: exceeded max depth of 10000"
    );
}

#[test]
fn deep_and_long_configs_need_no_deep_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let good = config(&image(), GITHUB);
            for config in [
                format!("{good}a:\n {}x\n", "- ".repeat(9_000)),
                format!("{good}a:\n {}x\n", "- ".repeat(400_000)),
                format!("{good}a: {}", "[".repeat(400_000)),
                format!("{good}a: {}", "{a: ".repeat(200_000)),
                format!("{good}{}", "? ".repeat(400_000)),
                format!("{good}a: [{}]\n", "&a x, *a, ".repeat(50_000)),
                format!("{good}{}", "  - &a\n    <<: *a\n".repeat(20_000)),
            ] {
                // Each returns, with requirements or an error.
                let _ = container_provenance_from_config(config.as_bytes());
            }

            // A chain of merges as long as a config has room for, read by
            // as many containers, is read once.
            let links = 9_000;
            let mut chain = format!("m0: &m0\n  image: {}\n  provenance: {FLOW}\n", image());
            for link in 1..links {
                chain.push_str(&format!("m{link}: &m{link}\n  <<: *m{}\n", link - 1));
            }
            chain.push_str("containers:\n");
            let last = links - 1;
            for _ in 0..links {
                chain.push_str(&format!("  - <<: *m{last}\n"));
            }
            let requirements = container_provenance_from_config(chain.as_bytes()).unwrap();
            assert_eq!(requirements.len(), links);
            assert_eq!(requirements.first(), Some(&flow("")));
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn arbitrary_configs_end_in_requirements_or_an_error() {
    const PIECES: &[&str] = &[
        "containers:",
        "\n  - ",
        "\n    ",
        "\n      ",
        "\n        ",
        "\n",
        "name: model",
        "image: example.com/model@sha256:abababababababababababababababababababababababababababababababab",
        "provenance:",
        "github:",
        "repository: a/b",
        "repository_id: 7",
        "workflow: w.yml",
        "ref: refs/heads/main",
        "{github: {repository: a/b, repository_id: 7, workflow: w.yml, ref: refs/heads/main}}",
        "<<: ",
        "&x ",
        "*x",
        "&y ",
        "*y",
        " ",
        ": ",
        "- ",
        "? ",
        "[",
        "]",
        "{",
        "}",
        ",",
        "#",
        "!!str ",
        "!!null ",
        "!",
        "~",
        "|",
        "'",
        "\"",
        "---\n",
        "\t",
        "a",
    ];
    // Every input starts as a config with a requirement, so that the
    // pieces after it land in and around what is read.
    let start = format!(
        "x: &x\n  name: model\n  image: {}\n  provenance: &y {FLOW}\ncontainers:\n  - *x",
        image()
    );
    let mut random = Random(1);
    let mut required = 0;
    for _ in 0..30_000 {
        let pieces = random.next(24);
        let text: String = std::iter::once(start.as_str())
            .chain((0..pieces).map(|_| PIECES[random.next(PIECES.len())]))
            .collect();
        // The read returns: it neither panics nor runs away.
        if container_provenance_from_config(text.as_bytes()).is_ok_and(|read| !read.is_empty()) {
            required += 1;
        }
    }
    assert!(required > 0, "no input stated a requirement");
}
