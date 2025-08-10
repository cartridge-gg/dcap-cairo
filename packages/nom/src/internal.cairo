/// Holds the result of parsing functions.
pub type IResult<I, O, E> = Result<(I, O), Err<E>>;

/// Contains information on needed data if a parser returned `Incomplete`.
#[derive(Drop, Debug, Clone)]
pub enum Needed {
    /// Needs more data, but we do not know how much
    Unknown,
    /// Contains the required data size in bytes
    Size: NonZero<usize>,
}

#[generate_trait]
pub impl NeededImpl of NeededTrait {
    fn new(s: usize) -> Needed {
        match TryInto::<usize, NonZero<usize>>::try_into(s) {
            Some(non_zero) => Needed::Size(non_zero),
            None => Needed::Unknown,
        }
    }
}

/// The `Err` enum indicates the parser was not successful.
#[derive(Drop, Debug)]
pub enum Err<E> {
    /// There was not enough data.
    Incomplete: Needed,
    /// The parser had an error (recoverable).
    Error: E,
    /// The parser had an unrecoverable error: we got to the right
    /// branch and we know other branches won't work, so backtrack
    /// as fast as possible.
    Failure: E,
}

#[generate_trait]
pub impl ErrImpl<E, +Drop<E>> of ErrTrait<E> {
    /// Applies the given function to the inner error
    fn map<E2, F, impl Fn: core::ops::Fn<F, (E,)>[Output: E2], +Drop<E2>, +Drop<F>>(
        self: Err<E>, f: F,
    ) -> Err<E2> {
        match self {
            Err::Incomplete(n) => Err::Incomplete(n),
            Err::Failure(t) => Err::Failure(f(t)),
            Err::Error(t) => Err::Error(f(t)),
        }
    }

    /// Automatically converts between errors if the underlying type supports it
    fn convert<F, +Drop<F>, +Into<F, E>>(e: Err<F>) -> Err<E> {
        // CAIRO: Using `.map()` directly causes a compiler panic.
        match e {
            Err::Incomplete(n) => Err::Incomplete(n),
            Err::Failure(t) => Err::Failure(Into::<F, E>::into(t)),
            Err::Error(t) => Err::Error(Into::<F, E>::into(t)),
        }
    }
}

/// All nom parsers implement this trait
pub trait Parser<SELF, I, O, E> {
    /// A parser takes in input type, and returns a `Result` containing
    /// either the remaining input and the output value, or an error
    fn parse(ref self: SELF, input: I) -> IResult<I, O, E>;
}
